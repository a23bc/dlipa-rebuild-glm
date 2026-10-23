import Foundation

/// Talks to the App Store private API.
///
/// Two things are mandatory for Apple to accept a request today, both proven by
/// experiment (see SIGNATURE_EXPERIMENT.md):
///
/// 1. The `X-Apple-ActionSignature` header over the exact body bytes.
/// 2. A trailing slash on the authenticate URL. Without it Apple answers 204
///    with an empty body and never looks at the request.
final class AppStoreClient {
    private let session: URLSession
    private let decoder = PropertyListDecoder()

    /// The address Apple redirected the authenticate endpoint to.
    ///
    /// The 2FA retry is a second call to `authenticate`, not a loop inside one
    /// call, so this has to outlive the first one. ipatool keeps the redirected
    /// URL in its retry loop and posts there again; going back to the generic
    /// endpoint on the code attempt is what produced a 404.
    private var authenticationPod: String?

    /// The UA the original DLiPA shipped. Apple gates the private bag on the
    /// Configurator UA: with a generic UA the response contains none of the
    /// sign-sap-* keys at all. The 2.17 UA was found to return a generic
    /// iTunes Store bag without SAP keys; 2.18 is the current Configurator
    /// release and returns the full bag with sign-sap-* endpoints.
    static let bagUserAgent =
        "Configurator/2.18 (Macintosh; OS X 15.3.2; 24D81) AppleWebKit/0620.2.4.11.6"

    /// ent/download expects this UA specifically.
    static let downloadUserAgent =
        "Configurator/2.18 (Macintosh; OS X 15.3.2; 24D81) AppleWebKit/0620.2.4.11.6"

    init() {
        let configuration = URLSessionConfiguration.default
        configuration.httpCookieStorage = HTTPCookieStorage.shared
        configuration.httpShouldSetCookies = true
        // The authenticate endpoint redirects to a Store pod; the body must be
        // re-signed at the destination rather than forwarded, so redirects are
        // handled manually.
        configuration.httpMaximumConnectionsPerHost = 4
        self.session = URLSession(configuration: configuration)
    }

    /// Drops everything about the account currently being signed in.
    ///
    /// A sign-in leaves two kinds of state behind: the pod address above, and
    /// the cookies URLSession stored. Both belong to the account that produced
    /// them. Signing in as somebody else with the first account's cookies looks
    /// to Apple like a session being hijacked, which is why a second account
    /// failed immediately after the first one had signed in.
    func resetSession() {
        authenticationPod = nil
        guard let storage = session.configuration.httpCookieStorage else { return }
        for cookie in storage.cookies ?? [] {
            storage.deleteCookie(cookie)
        }
    }

    // MARK: - Bag

    func fetchBag(guid: String) async throws -> StoreBag {
        var components = URLComponents(string: "https://init.itunes.apple.com/bag.xml")!
        components.queryItems = [URLQueryItem(name: "guid", value: guid)]
        var request = URLRequest(url: components.url!)
        request.httpMethod = "GET"
        request.setValue("application/xml", forHTTPHeaderField: "Accept")
        request.setValue(Self.bagUserAgent, forHTTPHeaderField: "User-Agent")
        AppLog.info("bag request: \(request.url?.absoluteString ?? "?"), UA: \(Self.bagUserAgent)", .network)

        let (data, response) = try await session.data(for: request)
        let http = response as? HTTPURLResponse
        AppLog.info("bag response: HTTP \(http?.statusCode ?? -1), \(data.count) bytes, content-type: \(http?.value(forHTTPHeaderField: "Content-Type") ?? "none"), final-url: \(http?.url?.absoluteString ?? "?")", .network)
        if data.count < 200 {
            AppLog.warn("bag response too short: " + (String(data: data, encoding: .utf8) ?? "<binary>"), .network)
        }
        try validate(response, data: data)
        let bag = try StoreBag.parse(xml: data)

        AppLog.info("bag received, " + String(data.count) + " bytes", .network)
        if bag.hasSAPConfiguration {
            AppLog.info("bag has SAP configuration, version " + String(bag.signSapVersion), .sap)
        } else {
            AppLog.warn("bag has no SAP configuration; signing will be unavailable", .sap)
        }
        if bag.volumeStoreDownloadProduct == nil {
            AppLog.warn("bag has no download endpoint", .network)
        }
        return bag
    }

    // MARK: - Authenticate

    struct Account {
        var email: String
        var passwordToken: String
        var dsid: String
        var storefront: String
        var pod: String
        var firstName: String
        var lastName: String
    }

    /// Signs in.
    ///
    /// Two-factor runs over two requests, and the shape is not obvious:
    ///
    /// - The code is appended to the password, not sent in a field of its own.
    /// - `attempt` counts the request: 1 for the password, 2 for the retry that
    ///   carries the code. Apple treats a code sent with `attempt` still at 1 as
    ///   a password typo, so the counter must advance.
    /// - The challenge is signalled by an EMPTY `failureType` together with
    ///   `customerMessage` equal to "MZFinance.BadLogin.Configurator_message".
    ///   There is no failure code to match on, and a response shaped this way
    ///   otherwise looks like a success: it has no passwordToken and no
    ///   dsPersonId, which is why they are checked below.
    func authenticate(email: String,
                      password: String,
                      authCode: String?,
                      guid: String,
                      endpoint: String,
                      signer: SAPSigner,
                      attempt: Int = 1) async throws -> Account {
        // A missing trailing slash gets a 204 and nothing else happens.
        let url = endpoint.hasSuffix("/") ? endpoint : endpoint + "/"
        AppLog.info("authenticating against " + url + " attempt " + String(attempt)
                    + (authCode == nil ? " (no 2FA)" : " (with 2FA)"), .auth)

        let code = authCode?.replacingOccurrences(of: " ", with: "") ?? ""

        // Where this request starts. A code-carrying attempt goes straight to
        // the pod the password attempt was redirected to; a fresh attempt
        // starts from the generic endpoint and forgets any earlier pod, because
        // the account may have changed.
        if authCode == nil || authCode!.isEmpty {
            authenticationPod = nil
        }
        var endpointNow = authenticationPod ?? url
        var sentAttempt = attempt
        var data = Data()
        var http: HTTPURLResponse?

        for pass in 0..<2 {
            let payload: [String: Any] = [
                "appleId": email,
                "attempt": String(sentAttempt),
                "guid": guid,
                "password": password + code,
                "rmp": "0",
                "why": "signIn",
            ]
            // The header says urlencoded but the body really is a plist; this
            // is what Apple accepts and what the signature must cover.
            let body = try PropertyListSerialization.data(
                fromPropertyList: payload, format: .xml, options: 0)

            var outcome: (Data, HTTPURLResponse)?
            for networkTry in 0..<Self.authenticationRequestAttempts {
                var attemptRequest = URLRequest(url: URL(string: endpointNow)!)
                attemptRequest.httpMethod = "POST"
                attemptRequest.setValue("application/x-www-form-urlencoded",
                                        forHTTPHeaderField: "Content-Type")
                attemptRequest.setValue(Self.bagUserAgent, forHTTPHeaderField: "User-Agent")
                attemptRequest.httpBody = body

                let result = try await signedRequest(
                    attemptRequest, signer: signer, redirects: 4)
                outcome = result
                if let settled = result.1.url?.absoluteString {
                    endpointNow = settled
                    authenticationPod = settled
                }

                // A Store pod answers 204, 403, 404, 429 or 5xx transiently.
                // ipatool retries those three times with a 10s / 20s backoff
                // instead of failing the sign-in.
                guard Self.isTransientAuthenticationStatus(result.1.statusCode),
                      networkTry < Self.authenticationRequestAttempts - 1 else { break }

                let delay = Self.authenticationRetryDelays[
                    min(networkTry, Self.authenticationRetryDelays.count - 1)]
                AppLog.warn("authenticate got HTTP " + String(result.1.statusCode)
                            + ", retrying in " + String(delay) + "s", .auth)
                try await Task.sleep(nanoseconds: UInt64(delay) * 1_000_000_000)
            }

            guard let finished = outcome else {
                throw StoreError.httpError(-1, "no response")
            }
            data = finished.0
            http = finished.1

            // Only the first pass, only without a code, and only for the
            // invalid-credentials code. Anything else ends the loop.
            guard pass == 0, sentAttempt == 1, authCode == nil else { break }
            let probe = (try? PropertyListSerialization.propertyList(
                from: data, options: [], format: nil)) as? [String: Any]
            guard (probe?["failureType"] as? String) == "-5000" else { break }

            AppLog.info("first credential attempt rejected; retrying once", .auth)
            sentAttempt = 2
        }

        guard let http else {
            throw StoreError.httpError(-1, "no response")
        }
        try validate(http, data: data)

        let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil)
            as? [String: Any] ?? [:]

        // Apple reports recoverable failures in the body with HTTP 200.
        let failure = plist["failureType"] as? String ?? ""
        let message = plist["customerMessage"] as? String ?? ""

        // The 2FA challenge. Empty failureType, and this specific message --
        // there is no code to match. ipatool calls this ErrAuthCodeRequired.
        if failure.isEmpty && message == "MZFinance.BadLogin.Configurator_message" {
            if authCode == nil || authCode!.isEmpty {
                AppLog.info("2FA required, asking for the code", .auth)
                throw StoreError.twoFactorRequired
            }
            // A code was supplied and Apple still asked: it was wrong or
            // expired. Sending the same one again cannot help.
            AppLog.error("2FA rejected after the code was supplied", .auth)
            throw StoreError.failureType("2FA", "apple did not accept the verification code; try a fresh one")
        }

        if !failure.isEmpty {
            AppLog.error("authenticate failed: failureType=\(failure) message=\(message)", .auth)
            throw StoreError.failureType(failure, message)
        }

        if message == "Your account is disabled." {
            throw StoreError.failureType("disabled", message)
        }

        let accountInfo = plist["accountInfo"] as? [String: Any] ?? [:]
        let address = accountInfo["address"] as? [String: Any] ?? [:]
        let passwordToken = plist["passwordToken"] as? String ?? ""
        let dsid = plist["dsPersonId"] as? String ?? ""

        // The success gate. Without both of these there is no session, and
        // treating the response as an account is what made a 2FA challenge
        // look like a completed sign-in.
        guard !passwordToken.isEmpty, !dsid.isEmpty else {
            AppLog.error("authenticate returned no session: passwordToken "
                         + String(passwordToken.count) + " chars, dsid "
                         + String(dsid.count) + " chars, message=\(message)", .auth)
            throw StoreError.failureType("no-session",
                                         "apple returned no usable authentication response")
        }

        // The sign-in is finished; the pod address belongs to it alone.
        authenticationPod = nil

        return Account(
            email: accountInfo["appleId"] as? String ?? email,
            passwordToken: passwordToken,
            dsid: dsid,
            storefront: headerValue(http, "X-Set-Apple-Store-Front") ?? "",
            pod: headerValue(http, "pod") ?? "",
            firstName: address["firstName"] as? String ?? "",
            lastName: address["lastName"] as? String ?? "")
    }

    // MARK: - Search

    /// Searches the public catalogue.
    ///
    /// No signature and no account are needed; this is the same endpoint the
    /// App Store itself uses. The country picks which catalogue is searched, so
    /// it comes from the active account's storefront when there is one.
    func search(term: String, country: String, limit: Int = 25) async throws -> [StoreApp] {
        var components = URLComponents(string: "https://itunes.apple.com/search")!
        components.queryItems = [
            URLQueryItem(name: "entity", value: "software"),
            URLQueryItem(name: "limit", value: String(limit)),
            URLQueryItem(name: "media", value: "software"),
            URLQueryItem(name: "term", value: term),
            URLQueryItem(name: "country", value: country),
        ]
        var request = URLRequest(url: components.url!)
        request.httpMethod = "GET"
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        AppLog.info("search: " + term + " in " + country, .network)

        let (data, response) = try await session.data(for: request)
        try validate(response, data: data)
        do {
            let decoded = try JSONDecoder().decode(StoreSearchResponse.self, from: data)
            AppLog.info("search returned " + String(decoded.resultCount) + " results", .network)
            return decoded.results
        } catch {
            AppLog.error("search decode failed: " + error.localizedDescription, .network)
            throw StoreError.failureType("search", "could not read the search response")
        }
    }

    // MARK: - Download

    /// The external version identifiers Apple knows for an app.
    struct VersionList {
        /// The version the store would hand out today.
        let latest: String
        /// Every version it still lists, newest first.
        let identifiers: [String]
    }

    /// Lists the versions available for an app.
    ///
    /// There is no version endpoint: the list rides along in the download
    /// product response as `softwareVersionExternalIdentifiers` in the item
    /// metadata.
    ///
    /// This is deliberately NOT the download request. ipatool-rs sends a
    /// trimmed body here -- salableAdamId, guid, creditDisplay, and nothing
    /// else, with no serialNumber and no X-Token -- so Apple treats it as a
    /// metadata query rather than a download and does not demand a licence.
    /// Sending the download shape is what kept answering 9610.
    func listVersions(appId: String,
                      guid: String,
                      account: Account,
                      bag: StoreBag) async throws -> VersionList {
        guard let endpoint = bag.volumeStoreDownloadProduct else {
            AppLog.error("bag has no download endpoint", .download)
            throw StoreError.noBagEndpoint
        }
        var components = URLComponents(string: endpoint)!
        components.queryItems = [URLQueryItem(name: "guid", value: guid)]

        var request = URLRequest(url: components.url!)
        request.httpMethod = "POST"
        request.setValue("application/x-apple-plist", forHTTPHeaderField: "Content-Type")
        request.setValue(account.dsid, forHTTPHeaderField: "iCloud-DSID")
        request.setValue(account.dsid, forHTTPHeaderField: "X-Dsid")

        let payload: [String: Any] = [
            // A string here; the download body uses an integer.
            "salableAdamId": appId,
            "guid": guid,
            "creditDisplay": "",
        ]
        request.httpBody = try PropertyListSerialization.data(
            fromPropertyList: payload, format: .xml, options: 0)

        AppLog.info("listing versions for " + appId, .download)
        let (data, response) = try await session.data(for: request)
        let status = (response as? HTTPURLResponse)?.statusCode ?? -1
        AppLog.info("version list returned HTTP " + String(status)
                    + ", " + String(data.count) + " bytes", .download)

        let plist = (try? PropertyListSerialization.propertyList(
            from: data, options: [], format: nil)) as? [String: Any] ?? [:]

        let failure = plist["failureType"] as? String ?? ""
        if !failure.isEmpty {
            let message = plist["customerMessage"] as? String ?? ""
            AppLog.error("version list failed: " + failure + " " + message, .download)
            throw StoreError.failureType(failure, message)
        }

        guard let items = plist["songList"] as? [Any],
              let first = items.first as? [String: Any] else {
            throw StoreError.failureType("versions", "apple returned no items")
        }
        let metadata = first["metadata"] as? [String: Any] ?? [:]
        let raw = metadata["softwareVersionExternalIdentifiers"] as? [Any] ?? []
        let identifiers = raw.map { String(describing: $0) }
        guard let latestRaw = metadata["softwareVersionExternalIdentifier"] else {
            throw StoreError.failureType("versions", "apple returned no latest version")
        }
        AppLog.info("versions for " + appId + ": " + String(identifiers.count), .download)
        return VersionList(latest: String(describing: latestRaw), identifiers: identifiers)
    }

    /// Requests a download and returns its URL.
    func requestDownload(appId: String,
                         externalVersionId: String?,
                         guid: String,
                         account: Account,
                         bag: StoreBag,
                         signer: SAPSigner) async throws -> URL {
        let plist = try await downloadProduct(
            appId: appId, externalVersionId: externalVersionId,
            guid: guid, account: account, bag: bag, signer: signer)

        guard let items = plist["songList"] as? [Any],
              let first = items.first as? [String: Any],
              let urlString = first["URL"] as? String,
              let url = URL(string: urlString) else {
            throw StoreError.failureType("Invalid response", "")
        }
        return url
    }

    // MARK: - Licence

    /// Attaches a free licence for an app to the account.
    ///
    /// `ent/download` answers 9610 while the account does not own the app, and
    /// even listing versions has to go through it, so nothing download-shaped
    /// works before this. It is a `buyProduct` at price 0 -- what ipatool-rs
    /// does before every download attempt.
    ///
    /// Not signed: ipatool-rs posts this one plain, with the token and DSID in
    /// headers instead.
    func acquireLicense(appId: String, guid: String, account: Account) async throws {
        let host = account.pod.isEmpty
            ? "buy.itunes.apple.com"
            : "p" + account.pod + "-buy.itunes.apple.com"
        guard let url = URL(string: "https://" + host
                             + "/WebObjects/MZFinance.woa/wa/buyProduct") else {
            throw StoreError.noBagEndpoint
        }

        // STDQ is the normal pricing parameter; GAME is the fallback Apple uses
        // for app purchases when STDQ is temporarily unavailable.
        for pricing in ["STDQ", "GAME"] {
            var request = URLRequest(url: url)
            request.httpMethod = "POST"
            request.setValue("application/x-apple-plist", forHTTPHeaderField: "Content-Type")
            request.setValue(account.dsid, forHTTPHeaderField: "iCloud-DSID")
            request.setValue(account.dsid, forHTTPHeaderField: "X-Dsid")
            request.setValue(account.storefront, forHTTPHeaderField: "X-Apple-Store-Front")
            request.setValue(account.passwordToken, forHTTPHeaderField: "X-Token")

            let payload: [String: Any] = [
                "appExtVrsId": "0",
                "hasAskedToFulfillPreorder": "true",
                "hasDoneAgeCheck": "true",
                "buyWithoutAuthorization": "true",
                "hasBeenAuthedForBuy": "true",
                "guid": guid,
                "needDiv": "0",
                "origPage": "Software-" + appId,
                "origPageLocation": "Buy",
                "price": "0",
                "pricingParameters": pricing,
                "productType": "C",
                // A string here, unlike the integer in the download body.
                "salableAdamId": appId,
            ]
            request.httpBody = try PropertyListSerialization.data(
                fromPropertyList: payload, format: .xml, options: 0)

            let (data, response) = try await session.data(for: request)
            let http = response as? HTTPURLResponse
            AppLog.info("buyProduct " + pricing + " returned "
                        + String(http?.statusCode ?? -1), .download)

            let plist = (try? PropertyListSerialization.propertyList(
                from: data, options: [], format: nil)) as? [String: Any] ?? [:]
            let failure = plist["failureType"] as? String ?? ""
            let message = plist["customerMessage"] as? String ?? ""

            if failure.isEmpty { return }
            // Already owned is the outcome we want.
            if failure == "5002"
                || message.lowercased().contains("license already exists") {
                AppLog.info("licence already present", .download)
                return
            }
            if failure == "2059" {
                AppLog.warn("buyProduct temporarily unavailable, backing off", .download)
                try? await Task.sleep(nanoseconds: 2_000_000_000)
                continue
            }
            AppLog.error("buyProduct failed: " + failure + " " + message, .download)
            throw StoreError.failureType(failure, message)
        }

        throw StoreError.failureType("2059",
                                     "apple kept reporting the item as temporarily unavailable")
    }

    /// The `ent/download` round trip, acquring a licence first if Apple says
    /// one is missing.
    private func downloadProduct(appId: String,
                                 externalVersionId: String?,
                                 guid: String,
                                 account: Account,
                                 bag: StoreBag,
                                 signer: SAPSigner) async throws -> [String: Any] {
        do {
            return try await downloadProductOnce(
                appId: appId, externalVersionId: externalVersionId,
                guid: guid, account: account, bag: bag, signer: signer)
        } catch {
            // 9610 is "no licence". Acquire one and try once more.
            guard let store = error as? StoreError,
                  case .failureType(let type, _) = store,
                  type == "9610" else {
                throw error
            }
            AppLog.info("download asked for a licence; acquiring one", .download)
            try await acquireLicense(appId: appId, guid: guid, account: account)
            return try await downloadProductOnce(
                appId: appId, externalVersionId: externalVersionId,
                guid: guid, account: account, bag: bag, signer: signer)
        }
    }

    private func downloadProductOnce(appId: String,
                                     externalVersionId: String?,
                                     guid: String,
                                     account: Account,
                                     bag: StoreBag,
                                     signer: SAPSigner) async throws -> [String: Any] {
        guard let endpoint = bag.volumeStoreDownloadProduct else {
            AppLog.error("no download endpoint in the bag", .download)
            throw StoreError.noBagEndpoint
        }
        AppLog.info("requesting download for " + appId + " from " + endpoint, .download)

        var components = URLComponents(string: endpoint)!
        components.queryItems = [URLQueryItem(name: "guid", value: guid)]

        var request = URLRequest(url: components.url!)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded; charset=utf-8",
                         forHTTPHeaderField: "Content-Type")
        request.setValue(Self.downloadUserAgent, forHTTPHeaderField: "User-Agent")
        request.setValue(account.storefront, forHTTPHeaderField: "X-Apple-Store-Front")
        request.setValue(account.passwordToken, forHTTPHeaderField: "X-Token")

        // Four fields, exactly as ipatool-rs builds this request
        // (download_request_body in src/api/download.rs):
        //
        //   salableAdamId   integer, not a string
        //   guid            the device identity
        //   creditDisplay   empty
        //   serialNumber    the literal "0"
        //
        // There is no kbsync. The Go ipatool sends one, but the Rust fork does
        // not, and it works: kbsync is the FairPlay blob a decryption session
        // wants, not something ent/download requires. That removes the whole
        // macOS 27 asset path from downloading.
        var payload: [String: Any] = [
            "creditDisplay": "",
            "guid": guid,
            // Integer, not a string: ipatool-rs sends an integer and its
            // tests pin the payload types.
            "salableAdamId": Int64(appId) ?? 0,
            "serialNumber": "0",
        ]
        if let externalVersionId {
            payload["externalVersionId"] = externalVersionId
        }
        request.httpBody = try PropertyListSerialization.data(
            fromPropertyList: payload, format: .xml, options: 0)

        let (data, response) = try await signedRequest(
            request, signer: signer, redirects: 4)
        try validate(response, data: data)

        let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil)
            as? [String: Any] ?? [:]

        if let failure = plist["failureType"] as? String, !failure.isEmpty {
            let message = plist["customerMessage"] as? String ?? ""
            throw StoreError.failureType(failure, message)
        }

        return plist
    }

    // MARK: - Signed transport

    /// Sends `request`, signing the body, and follows redirects by
    /// re-signing at each hop.
    ///
    /// Two details matter, both learned the hard way:
    ///
    /// - A 303 asks for a GET, so the body is gone and there is nothing to
    ///   sign. Treating it as replayable would re-POST incorrectly.
    /// - `Location` can be relative, so resolve it against the current URL.
    private func signedRequest(_ request: URLRequest,
                               signer: SAPSigner,
                               redirects: Int) async throws -> (Data, HTTPURLResponse) {
        var current = request

        for _ in 0...max(redirects, 0) {
            var signed = current
            // Sign the exact bytes that go on the wire. Apple validates the
            // signature over the body, so this must happen after the body is
            // final and before the request is dispatched.
            let body = signed.httpBody ?? Data()
            signed.setValue(try signer.signatureHeaderValue(for: body),
                           forHTTPHeaderField: "X-Apple-ActionSignature")

            let (data, response) = try await session.data(for: signed)
            guard let http = response as? HTTPURLResponse else {
                AppLog.error("response was not HTTP", .network)
                throw StoreError.httpError(-1, "not an HTTP response")
            }

            // The status code plus whether the signature was attached is the
            // pair that explains most failures: 403 with a signature present
            // means Apple rejected it, 403 with no signature means it was never
            // sent.
            AppLog.info("signed request to " + (signed.url?.absoluteString ?? "?")
                        + " returned " + String(http.statusCode)
                        + ", body " + String(body.count) + " bytes", .network)
            if http.statusCode == 403 {
                let hadSignature = signed.value(forHTTPHeaderField: "X-Apple-ActionSignature")
                AppLog.error("403 from " + (signed.url?.host ?? "?")
                             + ", signature attached: " + String(hadSignature != nil)
                             + ", signature length: " + String(hadSignature?.count ?? 0)
                             + ", body length: " + String(body.count), .network)
                // Apple puts the reason in the body. Without it a 403 is just
                // a number, and the difference between "bad signature",
                // "wrong endpoint" and "account locked" is the whole answer.
                AppLog.error("403 body: " + (String(data: data, encoding: .utf8)
                             ?? "<(data.count) binary bytes>"), .network)
                AppLog.error("403 headers: "
                             + String(describing: http.allHeaderFields), .network)
            }

            // A 3xx that should be replayed as-is carries a Location and keeps
            // the body. A 303 does not: it converts to a GET, so the body is
            // gone and re-signing is meaningless.
            guard isReplayableRedirect(http.statusCode),
                  let location = http.value(forHTTPHeaderField: "Location"),
                  !location.isEmpty else {
                return (data, http)
            }

            guard let next = resolvedURL(location, relativeTo: signed.url) else {
                // An unresolvable Location is a dead end; surface the redirect.
                return (data, http)
            }

            AppLog.debug("following redirect to " + next.absoluteString, .network)
            var redirected = URLRequest(url: next)
            redirected.httpMethod = signed.httpMethod
            redirected.httpBody = signed.httpBody
            // Copy the other headers but drop the signature; it is recomputed
            // at the top of the loop over the new body.
            for (key, value) in signed.allHTTPHeaderFields ?? [:] where key != "X-Apple-ActionSignature" {
                redirected.setValue(value, forHTTPHeaderField: key)
            }
            current = redirected
        }

        throw StoreError.httpError(310, "too many redirects")
    }

    /// How many times a single authentication request is sent. ipatool uses
    /// three, with the delays below between them.
    private static let authenticationRequestAttempts = 3

    /// 10s then 20s, capped at 30s the way ipatool caps it.
    private static let authenticationRetryDelays: [UInt64] = [10, 20]

    /// Statuses a Store pod returns when it is not ready to answer. Treating
    /// these as final is what surfaced a 404 to the user on the 2FA attempt.
    private static func isTransientAuthenticationStatus(_ statusCode: Int) -> Bool {
        switch statusCode {
        case 204, 403, 404, 429:
            return true
        default:
            return statusCode / 100 == 5
        }
    }

    /// Redirect codes whose body must be replayed at the destination.
    ///
    /// 303 is excluded on purpose: it converts the request to a GET, so there
    /// is no body left to sign.
    private func isReplayableRedirect(_ statusCode: Int) -> Bool {
        switch statusCode {
        case 301, 302, 307, 308:
            return true
        default:
            return false
        }
    }

    /// Resolves a possibly relative Location against the request URL.
    private func resolvedURL(_ location: String, relativeTo base: URL?) -> URL? {
        if let absolute = URL(string: location), absolute.scheme != nil {
            return absolute
        }
        guard let base else { return nil }
        return URL(string: location, relativeTo: base)?.absoluteURL
    }
    // MARK: - Helpers

    private func validate(_ response: URLResponse, data: Data) throws {
        guard let http = response as? HTTPURLResponse else {
            throw StoreError.httpError(-1, "")
        }
        // A 403 here almost always means the signature was missing or stale.
        guard (200..<300).contains(http.statusCode) else {
            let body = String(data: data, encoding: .utf8) ?? ""
            throw StoreError.httpError(http.statusCode, String(body.prefix(200)))
        }
    }

    private func headerValue(_ response: URLResponse, _ name: String) -> String? {
        (response as? HTTPURLResponse)?.value(forHTTPHeaderField: name)
    }
}
