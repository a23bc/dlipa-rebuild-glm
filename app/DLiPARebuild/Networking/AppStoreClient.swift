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
        // Automatic cookie handling is off on purpose.
        //
        // With it on, URLSession consumes Set-Cookie into HTTPCookieStorage and
        // removes it from the response headers. On this platform the storage then
        // reports nothing for itunes.apple.com, so the cookies end up nowhere:
        // gone from the headers we can read, absent from the jar we can query.
        // That is why every download logged "store cookies: none" and replayed a
        // single 17-character cookie while the authenticate response had just
        // handed over seventeen.
        //
        // With it off, Set-Cookie stays in allHeaderFields, captureCookies sees
        // all of them, and the replay header carries the real session.
        configuration.httpShouldSetCookies = false
        configuration.httpCookieStorage = HTTPCookieStorage.shared
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
        // The hand-copied jar is a second cookie store, and it outlived this
        // reset: switching accounts kept the previous one's mz_at_ssl-* and
        // X-Token and replayed them with the new account's DSID.
        capturedCookieHeader = ""
        capturedCookieValues = [:]
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
        /// The store sets an X-Token cookie at sign-in. That value is the session
        /// credential -- the 52 character passwordToken is refused by the store
        /// with 2002 and the 32 character clearToken with 2034.
        var sessionToken: String
        /// authenticate also returns a 32 character clearToken. Its name says it
        /// is the usable form, so it is carried alongside passwordToken and
        /// tried as X-Token -- the 52 character one is refused with 2002.
        var clearToken: String
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

            // Checked per pass because a redirect can move endpointNow onto a
            // pod the earlier attempt was sent to. This request carries the
            // Apple ID password, so the destination is not negotiable.
            let attemptURL = try Self.trustedEndpoint(endpointNow)

            var outcome: (Data, HTTPURLResponse)?
            for networkTry in 0..<Self.authenticationRequestAttempts {
                var attemptRequest = URLRequest(url: attemptURL)
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
        let clearToken = plist["clearToken"] as? String ?? ""
        let dsid = plist["dsPersonId"] as? String ?? ""

        // Field names and sizes, never values. The store rejects the token this
        // parses with 2002 "Your password has changed", immediately after a
        // fresh 2FA sign-in, so the question is whether the real session token
        // lives under a different key -- and only a key map can answer that.
        let summary = plist.keys.sorted().map { key -> String in
            switch plist[key] {
            case let value as String: return key + "(" + String(value.count) + ")"
            case let value as [String: Any]: return key + "{" + String(value.count) + "}"
            case let value as [Any]: return key + "[" + String(value.count) + "]"
            default: return key + "(?)"
            }
        }.joined(separator: ", ")
        AppLog.info("authenticate keys: " + summary, .auth)
        AppLog.info("authenticate accountInfo keys: "
                    + accountInfo.keys.sorted().joined(separator: ", "), .auth)

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

        // What the store session is actually made of. If Apple sets no cookie
        // here, nothing downstream can be authenticated with a token alone, and
        // the classic download endpoint's "sign in required" makes sense.
        if let storage = session.configuration.httpCookieStorage {
            let names = (storage.cookies ?? [])
                .filter { $0.domain.contains("itunes.apple.com") }
                .map { $0.name }
            AppLog.info("after authenticate, store cookies: "
                        + (names.isEmpty ? "none" : names.joined(separator: ", ")), .auth)
        }

        // The sign-in is finished; the pod address belongs to it alone.
        authenticationPod = nil

        return Account(
            email: accountInfo["appleId"] as? String ?? email,
            passwordToken: passwordToken,
            sessionToken: capturedCookieValues["X-Token"] ?? passwordToken,
            clearToken: clearToken,
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
        /// The version the store would hand out today, when Apple says which
        /// one it is. The dictionary-shaped response does not.
        let latest: String?
        /// Every version it still lists.
        let identifiers: [String]
    }

    /// Lists the versions available for an app, acquiring a licence if Apple
    /// asks for one.
    ///
    /// Uses the signed download request. Two cheaper variants were tried and
    /// both failed for reasons that had nothing to do with the licence: with
    /// the DSID headers only, Apple answered 401 and an empty body; unsigned
    /// with a trimmed body, it answered 500. The signed request is the one that
    /// produces a real response, so the only variable left is the licence,
    /// which downloadProduct buys and retries on.
    func listVersions(appId: String,
                      guid: String,
                      account: Account,
                      bag: StoreBag,
                      signer: SAPSigner) async throws -> VersionList {
        let plist = try await downloadProduct(
            appId: appId, externalVersionId: nil,
            guid: guid, account: account, bag: bag, signer: signer)

        let failure = plist["failureType"] as? String ?? ""
        // 5002 is "licence already exists". Alongside a songList it is not an
        // error at all: the list follows. ipatool-rs makes the same exception.
        let benign = (failure == "5002" && plist["songList"] != nil)
        if !failure.isEmpty && !benign {
            let message = plist["customerMessage"] as? String ?? ""
            AppLog.error("version list failed: " + failure + " " + message, .download)
            throw StoreError.failureType(failure, message)
        }

        // songList comes in two shapes and both are valid: an array whose first
        // item carries metadata, or a dictionary keyed by external version id.
        guard let songList = plist["songList"] else {
            AppLog.error("version list had no songList; keys: "
                         + plist.keys.sorted().joined(separator: ", "), .download)
            throw StoreError.failureType("versions", "apple returned no songList")
        }

        var identifiers: [String] = []
        var latest: String?

        if let map = songList as? [String: Any] {
            // Dictionary shape: the keys are the version ids and there is no
            // separate "latest" field.
            identifiers = map.keys.sorted { lhs, rhs in
                (Int64(lhs) ?? 0) > (Int64(rhs) ?? 0)
            }
        } else if let array = songList as? [Any],
                  let first = array.first as? [String: Any] {
            // Array shape: metadata sits in a nested dictionary, or directly on
            // the item under the externalVersionIdentifiers names.
            let source = (first["metadata"] as? [String: Any]) ?? first
            let raw = (source["softwareVersionExternalIdentifiers"] as? [Any])
                ?? (source["externalVersionIdentifiers"] as? [Any])
                ?? []
            identifiers = raw.map { String(describing: $0) }
            if let value = source["softwareVersionExternalIdentifier"]
                ?? source["externalVersionIdentifier"] {
                latest = String(describing: value)
            }
        }

        guard !identifiers.isEmpty else {
            AppLog.error("version list had no identifiers; item keys: "
                         + ((songList as? [Any])?.first
                            .flatMap { ($0 as? [String: Any])?.keys.sorted().joined(separator: ", ") }
                            ?? "not an array"), .download)
            throw StoreError.failureType("versions", "apple returned no versions")
        }

        AppLog.info("versions for " + appId + ": " + String(identifiers.count)
                    + ", latest " + (latest ?? "unknown"), .download)
        return VersionList(latest: latest, identifiers: identifiers)
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

    /// Cookies the store hands out, collected by hand and replayed explicitly.
    ///
    /// URLSession is configured to keep cookies, yet the store still ends up
    /// with none after a sign-in, so nothing downstream can prove a session.
    /// Reading them straight off the response headers and sending them back
    /// removes the storage question from the picture, and the log names them so
    /// an empty set is visible rather than inferred.
    private var capturedCookieHeader = ""
    private var capturedCookieValues: [String: String] = [:]

    private func captureCookies(from http: HTTPURLResponse) {
        // Cookies belong to the host that set them. Bag and store endpoints are
        // always Apple's; anything else is either a redirect we should not be
        // following with credentials or an endpoint that should never see them.
        guard Self.isAppleHost(http.url?.host) else {
            AppLog.warn("ignoring Set-Cookie from non-Apple host "
                        + (http.url?.host ?? "?"), .network)
            return
        }
        var raw: [String] = []
        for (key, value) in http.allHeaderFields {
            if String(describing: key).lowercased() == "set-cookie" {
                raw.append(String(describing: value))
            }
        }
        guard !raw.isEmpty else { return }

        var pairs = capturedCookieHeader.isEmpty
            ? [String]()
            : capturedCookieHeader.components(separatedBy: "; ")
        for header in raw {
            for piece in header.components(separatedBy: ",") {
                let first = piece.components(separatedBy: ";").first ?? ""
                let trimmed = first.trimmingCharacters(in: .whitespaces)
                guard let eq = trimmed.firstIndex(of: "=") else { continue }
                let name = String(trimmed[trimmed.startIndex..<eq])
                guard !name.isEmpty else { continue }
                pairs.removeAll { $0.hasPrefix(name + "=") }
                pairs.append(trimmed)
            }
        }
        capturedCookieHeader = pairs.joined(separator: "; ")
        for pair in pairs {
            let parts = pair.components(separatedBy: "=")
            guard parts.count >= 2 else { continue }
            capturedCookieValues[parts[0]] = parts.dropFirst().joined(separator: "=")
        }
        let names = pairs.map { $0.components(separatedBy: "=").first ?? "?" }
        // Both numbers matter: what this response exposed, and what has
        // accumulated. A response that exposes nothing is the difference between
        // "Apple sent no cookies" and "we could not see them".
        let exposed = raw.count
        let total = capturedCookieValues.count
        AppLog.info("Set-Cookie from " + (http.url?.host ?? "?") + ": "
                    + String(exposed) + " header(s), total " + String(total)
                    + " cookies: " + names.joined(separator: ", "), .network)
    }

    /// Header names with the values of anything carrying a credential replaced
    /// by its length. Names and lengths still say what the response contained.
    private static func redactedHeaders(_ headers: [AnyHashable: Any]) -> String {
        let sensitive = ["set-cookie", "cookie", "x-token", "authorization",
                         "x-apple-dsid", "x-icloud-dsid", "x-dsid"]
        let parts: [String] = headers.keys.map { key in
            let name = String(describing: key)
            let lower = name.lowercased()
            let value = String(describing: headers[key] ?? "")
            if sensitive.contains(where: { lower.contains($0) }) {
                return name + "=<redacted " + String(value.count) + " chars>"
            }
            return name + "=" + value
        }
        return parts.sorted().joined(separator: ", ")
    }

    /// Whether a header carries something that authorises the request.
    private static func isCredentialHeader(_ name: String) -> Bool {
        let lower = name.lowercased()
        return lower == "cookie"
            || lower == "authorization"
            || lower.hasPrefix("x-token")
            || lower.contains("dsid")
            || lower.contains("icloud-dsid")
    }

    /// Parses an endpoint that will carry a credential.
    ///
    /// Everything sent to these endpoints -- the Apple ID password, the session
    /// cookie, the account's token -- is derived from the bag, and the bag is a
    /// response. A tampered or merely unusual one could name an http URL or
    /// somebody else's host, and nothing downstream checked. The Go runtime has
    /// had this rule all along (internal/store/emulator/client.go, allowedURL);
    /// the Swift path did not.
    static func trustedEndpoint(_ string: String) throws -> URL {
        guard let url = URL(string: string),
              url.scheme?.lowercased() == "https",
              isAppleHost(url.host) else {
            throw StoreError.untrustedEndpoint(string)
        }

        return url
    }

    /// Whether a host is one this client may hand credentials to. Apple only.
    static func isAppleHost(_ host: String?) -> Bool {
        guard let host = host?.lowercased(), !host.isEmpty else { return false }
        return host == "apple.com" || host.hasSuffix(".apple.com")
    }

    /// Enough of an identifier to tell two accounts apart in a log, not enough
    /// to be an identifier. Logs get shared.
    static func masked(_ value: String) -> String {
        guard value.count > 4 else { return value.isEmpty ? "none" : "****" }
        return "****" + String(value.suffix(3))
    }

    // MARK: - Machine authorisation

    /// Binds this device to the account.
    ///
    /// authenticate proves the password and returns a token, but it leaves the
    /// store with no session: HTTPCookieStorage ends up with zero itunes.apple.com
    /// cookies, and every download answers 2042 "Sign In to the iTunes Store".
    /// The real client's next step is this call.
    ///
    /// There is no reference implementation to copy -- ipatool gets this from
    /// the emulated Store framework, and probeapp the same way -- so the body
    /// shapes are tried in one pass and each result is logged, rather than one
    /// build per guess.
    func authorizeMachine(account: Account,
                          guid: String,
                          bag: StoreBag,
                          signer: SAPSigner) async -> Bool {
        guard let endpoint = bag.authorizeMachine, let url = URL(string: endpoint) else {
            AppLog.warn("bag has no authorizeMachine endpoint", .auth)
            return false
        }
        // The token is minted on the pod host (p<n>-buy...authenticate/?Pod=n)
        // while the bag names the generic host for this call. A token issued by
        // one and presented to the other is exactly the kind of mismatch that
        // reads back as "your password has changed", so both hosts are tried.
        // Pod host first: the token was minted there.
        var urls: [(String, URL)] = []
        if !account.pod.isEmpty,
           var components = URLComponents(url: url, resolvingAgainstBaseURL: false) {
            components.host = "p" + account.pod + "-buy.itunes.apple.com"
            if let podURL = components.url { urls.append(("pod", podURL)) }
        }
        urls.append(("bag", url))

        let name = "DLiPA Rebuild"
        let payload: [String: Any] = ["guid": guid, "serialNumber": guid,
                                      "machineName": name]

        // clearToken first, and alone until it has been given a clean shot.
        //
        // It is the credential the store actually recognises: offered as X-Token
        // it answers 2034 ExpiredPasswordToken, while passwordToken answers 2002
        // BadPasswordToken. In the last run the passwordToken attempts ran first
        // and by the time clearToken was tried the session had been invalidated,
        // so ordering may be the whole story. Signed is dropped too -- it never
        // changed a response here.
        // clearToken only. passwordToken answers 2002 every time and adding it
        // just spends attempts on a credential the store has never accepted.
        let tokens: [(String, String)] = [("session", account.sessionToken),
                                          ("clearToken", account.clearToken)]

        for (hostLabel, hostURL) in urls {
            for (tokenLabel, tokenValue) in tokens {
            for signed in [false] {
                let label = hostLabel + "/" + tokenLabel
                var request = URLRequest(url: hostURL)
                request.httpMethod = "POST"
                request.setValue("application/x-apple-plist",
                                 forHTTPHeaderField: "Content-Type")
                request.setValue(account.dsid, forHTTPHeaderField: "iCloud-DSID")
                request.setValue(account.dsid, forHTTPHeaderField: "X-Dsid")
                request.setValue(tokenValue, forHTTPHeaderField: "X-Token")
                request.httpBody = try? PropertyListSerialization.data(
                    fromPropertyList: payload, format: .xml, options: 0)

                let tag = "authorizeMachine [" + label + "]"
                do {
                    let data: Data
                    let status: Int
                    if signed {
                        let (d, http) = try await signedRequest(
                            request, signer: signer, redirects: 3)
                        data = d
                        status = http.statusCode
                    } else {
                        let (d, r) = try await session.data(for: request)
                        data = d
                        status = (r as? HTTPURLResponse)?.statusCode ?? -1
                    }
                    let preview = String(data: data.prefix(400), encoding: .utf8) ?? "<binary>"
                    AppLog.info(tag + " HTTP " + String(status) + ", "
                                + String(data.count) + " bytes", .auth)
                    let parsed = (try? PropertyListSerialization.propertyList(
                        from: data, options: [], format: nil)) as? [String: Any] ?? [:]
                    let code = (parsed["metrics"] as? [String: Any])?["messageCode"] as? String
                    if (200..<300).contains(status) && code == nil
                        && (parsed["failureType"] as? String ?? "").isEmpty {
                        AppLog.info(tag + " accepted; the machine is authorised", .auth)
                        return true
                    }
                    if !preview.isEmpty {
                        AppLog.info("  body: " + preview, .auth)
                    }
                } catch {
                    AppLog.warn(tag + " failed: " + error.localizedDescription, .auth)
                }
            }
            }
        }
        AppLog.error("authorizeMachine: no attempt was accepted", .auth)
        return false
    }

    // MARK: - Licence

    /// Attaches a free licence for an app to the account.
    ///
    /// Copied from ipatool (pkg/appstore/appstore_purchase.go), including the
    /// part that is easy to get wrong:
    ///
    ///     if res.StatusCode == http.StatusInternalServerError {
    ///         return ErrLicenseAlreadyExists
    ///     }
    ///
    /// A 500 from buyProduct means the licence is already there. Treating it as
    /// a failure is why this loop kept reporting "licence required" after a
    /// purchase that had actually worked.
    ///
    /// The URL is the one the bag names, not the MZFinance.woa path hardcoded
    /// in ipatool. Both were tried on the device, signed:
    ///
    ///     bag's MZBuy.woa      -> 500
    ///     ipatool's MZFinance  -> 400
    ///
    /// and 500 is the code that means "licence exists". The body sends
    /// salableAdamId as an integer, which is what ipatool passes.
    func acquireLicense(appId: String,
                        guid: String,
                        account: Account,
                        bag: StoreBag,
                        signer: SAPSigner) async throws {
        let podPrefix = account.pod.isEmpty ? "" : "p" + account.pod + "-"
        let fallback = "https://" + podPrefix
            + "buy.itunes.apple.com/WebObjects/MZBuy.woa/wa/buyProduct"
        guard let url = try? Self.trustedEndpoint(bag.buyProduct ?? fallback) else {
            throw StoreError.noBagEndpoint
        }
        AppLog.info("buyProduct " + url.absoluteString + " for " + appId
                    + " (storefront "
                    + (account.storefront.isEmpty ? "none" : account.storefront) + ")", .download)

        var lastError: Error?
        // STDQ is the normal pricing parameter; GAME is the Apple Arcade one
        // ipatool falls back to when the item reports as temporarily
        // unavailable.
        for pricing in ["STDQ", "GAME"] {
            var request = URLRequest(url: url)
            request.httpMethod = "POST"
            request.setValue("application/x-apple-plist", forHTTPHeaderField: "Content-Type")
            request.setValue(account.dsid, forHTTPHeaderField: "iCloud-DSID")
            request.setValue(account.dsid, forHTTPHeaderField: "X-Dsid")
            request.setValue(account.storefront, forHTTPHeaderField: "X-Apple-Store-Front")
            request.setValue(account.sessionToken.isEmpty ? account.passwordToken
                                                          : account.sessionToken,
                             forHTTPHeaderField: "X-Token")
            if !capturedCookieHeader.isEmpty {
                request.setValue(capturedCookieHeader, forHTTPHeaderField: "Cookie")
            }

            let payload: [String: Any] = [
                "appExtVrsId": "0",
                "hasAskedToFulfillPreorder": "true",
                "buyWithoutAuthorization": "true",
                "hasDoneAgeCheck": "true",
                "guid": guid,
                "needDiv": "0",
                "origPage": "Software-" + appId,
                "origPageLocation": "Buy",
                "price": "0",
                "pricingParameters": pricing,
                "productType": "C",
                // Integer, as ipatool sends it.
                "salableAdamId": Int64(appId) ?? 0,
            ]
            request.httpBody = try PropertyListSerialization.data(
                fromPropertyList: payload, format: .xml, options: 0)

            // Signed. ipatool does not sign this, but its XMLPayload is encoded
            // and sent by the emulated Store framework, which brings its own
            // session. Posted raw, the same request gets 400 unsigned and 500
            // signed, and 500 is the code ipatool reads as "licence exists".
            let (data, signedResponse) = try await signedRequest(
                request, signer: signer, redirects: 3)
            let status = signedResponse.statusCode
            let bodyText = String(data: data, encoding: .utf8) ?? ""
            AppLog.info("buyProduct " + pricing + " returned HTTP " + String(status)
                        + ", " + String(data.count) + " bytes", .download)
            if !bodyText.isEmpty {
                AppLog.info("buyProduct " + pricing + " body: "
                            + String(bodyText.prefix(800)), .download)
            }

            let plist = (try? PropertyListSerialization.propertyList(
                from: data, options: [], format: nil)) as? [String: Any] ?? [:]
            let failure = plist["failureType"] as? String ?? ""
            let message = plist["customerMessage"] as? String ?? ""
            let docType = plist["jingleDocType"] as? String ?? ""

            // The mapping ipatool relies on.
            if status == 500 {
                AppLog.info("buyProduct answered 500; per ipatool that means the "
                            + "licence already exists", .download)
                return
            }
            if failure == "5002" || failure == "2059" {
                if failure == "5002" {
                    AppLog.info("licence already present", .download)
                    return
                }
                lastError = StoreError.failureType(failure, message)
                try? await Task.sleep(nanoseconds: 2_000_000_000)
                continue
            }
            if !failure.isEmpty {
                AppLog.error("buyProduct failed: " + failure + " " + message, .download)
                throw StoreError.failureType(failure, message)
            }
            if (200..<300).contains(status) && (docType == "purchaseSuccess" || docType.isEmpty) {
                AppLog.info("licence granted", .download)
                return
            }
            lastError = StoreError.failureType("purchase", "apple did not confirm the purchase")
        }

        throw lastError ?? StoreError.failureType("purchase", "no purchase response")
    }

    /// The `ent/download` round trip, acquring a licence first if Apple says
    /// one is missing.
    private func downloadProduct(appId: String,
                                 externalVersionId: String?,
                                 guid: String,
                                 account: Account,
                                 bag: StoreBag,
                                 signer: SAPSigner) async throws -> [String: Any] {
        var acquiredLicence = false
        var discardedBlob = false

        while true {
            do {
                return try await downloadProductOnce(
                    appId: appId, externalVersionId: externalVersionId,
                    guid: guid, account: account, bag: bag, signer: signer)
            } catch {
                guard let store = error as? StoreError,
                      case .failureType(let type, _) = store else {
                    throw error
                }

                // 9610 is "no licence". Acquire one and try once more.
                if type == "9610", !acquiredLicence {
                    acquiredLicence = true
                    AppLog.info("download asked for a licence; acquiring one", .download)
                    try await acquireLicense(appId: appId, guid: guid, account: account,
                                             bag: bag, signer: signer)

                    continue
                }

                // A 9610 that outlived the licence, a 2034 expired token and a
                // 2042 "sign in" are all what Apple answers when the kbsync
                // blob no longer describes this account or this device. The
                // blob was cached for the life of the process and
                // invalidateKBSync had no callers, so the only recovery was to
                // kill the app -- the cache is in memory.
                if Self.staleBlobFailureTypes.contains(type), !discardedBlob {
                    discardedBlob = true
                    AppLog.info("download answered " + type
                                + "; discarding the cached kbsync blob and retrying", .download)
                    signer.invalidateKBSync(dsid: account.dsid)

                    continue
                }

                throw error
            }
        }
    }

    /// Failure types that mean "the blob is stale", not "the request is wrong".
    ///
    /// 2034 and 2042 are about the session the blob is bound to; 9610 is listed
    /// because a licence that was granted and still draws "licence required" is
    /// the same symptom one layer up.
    private static let staleBlobFailureTypes: Set<String> = ["9610", "2042", "2034"]

    /// ent/download first, classic second -- the order ipatool uses.
    ///
    /// The two endpoints fail differently and that difference is the point:
    /// ent/download answers 9610, a business-level "licence required", while
    /// the classic endpoint answers 2042, "sign in". A 9610 therefore proves
    /// the request was authenticated and only the licence is missing, so it must
    /// not be swallowed by a fallback.
    private func downloadProductOnce(appId: String,
                                     externalVersionId: String?,
                                     guid: String,
                                     account: Account,
                                     bag: StoreBag,
                                     signer: SAPSigner) async throws -> [String: Any] {
        if let ent = bag.volumeStoreDownloadProduct {
            do {
                return try await entDownload(appId: appId,
                                             externalVersionId: externalVersionId,
                                             guid: guid, account: account,
                                             endpoint: ent, signer: signer)
            } catch let error as StoreError {
                // A licence error is an answer, not a transport problem.
                if case .failureType(let type, _) = error, type == "9610" {
                    throw error
                }
                AppLog.warn("ent/download did not serve this app ("
                            + error.localizedDescription
                            + "); trying the classic endpoint", .download)
            }
        }
        return try await classicDownload(appId: appId,
                                         externalVersionId: externalVersionId,
                                         guid: guid, account: account,
                                         bag: bag, signer: signer)
    }

    /// The signed ent/download call.
    private func entDownload(appId: String,
                             externalVersionId: String?,
                             guid: String,
                             account: Account,
                             endpoint: String,
                             signer: SAPSigner) async throws -> [String: Any] {
        guard var components = URLComponents(url: try Self.trustedEndpoint(endpoint),
                                             resolvingAgainstBaseURL: false) else {
            throw StoreError.untrustedEndpoint(endpoint)
        }
        components.queryItems = [URLQueryItem(name: "guid", value: guid)]

        var request = URLRequest(url: components.url!)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded; charset=utf-8",
                         forHTTPHeaderField: "Content-Type")
        request.setValue(Self.downloadUserAgent, forHTTPHeaderField: "User-Agent")
        // ent/download does want the store-front. ipatool sets it from the
        // account (appstore_kbsync.go:122) alongside the Configurator agent and
        // the store token; the earlier note here claiming otherwise was written
        // while the request was still missing kbsync and everything else.
        // ent/download exists because of kbsync: the blob is what binds the
        // download to this account and device. Without it the request is the
        // classic one wearing a different URL. Field by field this mirrors
        // appstore_kbsync.go:124.
        let blob = try signer.kbsync(dsid: account.dsid)
        let serial = try signer.serialNumber()
        let payload: [String: Any] = [
            "creditDisplay": "",
            "guid": guid,
            "kbsync": blob.base64EncodedString(),
            // A string upstream (strconv.FormatInt), not a number.
            "salableAdamId": appId,
            "serialNumber": serial,
            // Always present, empty when unpinned.
            "externalVersionId": externalVersionId ?? "",
        ]
        let body = try PropertyListSerialization.data(
            fromPropertyList: payload, format: .xml, options: 0)

        // Which credential ent/download wants is not settled by reading the
        // source. Upstream sends PasswordToken plus both DSID headers
        // (appstore_kbsync.go:112-131 layered on downloadProductRequest), but an
        // earlier run here saw the DSID headers turn this into an empty 500 --
        // with a body that was still missing kbsync, so the observation does not
        // transfer. Rather than spend a build per variable, send the
        // combinations once and let the log say which one was answered.
        // One attempt: upstream's shape, plus the replayed cookies. The
        // four-way credential matrix is gone -- every combination returned the
        // same 500 with an empty body, so the credential was never the variable.
        let variants: [(String, String, Bool)] = [
            ("cookie+passwordToken+dsid", account.passwordToken, true),
        ]

        var rejected: (failure: String, message: String) = ("", "")
        var lastStatus = -1

        for (name, token, sendDSID) in variants {
            var attempt = request
            attempt.httpBody = body
            attempt.setValue(account.storefront, forHTTPHeaderField: "X-Apple-Store-Front")
            if !token.isEmpty {
                attempt.setValue(token, forHTTPHeaderField: "X-Token")
            }
            if sendDSID {
                attempt.setValue(account.dsid, forHTTPHeaderField: "iCloud-DSID")
                attempt.setValue(account.dsid, forHTTPHeaderField: "X-Dsid")
            }
            if !capturedCookieHeader.isEmpty {
                attempt.setValue(capturedCookieHeader, forHTTPHeaderField: "Cookie")
            }

            // Upstream sets NoRedirects for ent/download: X-Token must not be
            // forwarded to wherever a redirect points.
            let (data, http) = try await signedRequest(attempt, signer: signer,
                                                       redirects: 0)
            lastStatus = http.statusCode
            let plist = (try? PropertyListSerialization.propertyList(
                from: data, options: [], format: nil)) as? [String: Any] ?? [:]
            let failure = plist["failureType"] as? String ?? ""
            AppLog.info("ent/download[" + name + "] HTTP " + String(http.statusCode)
                        + ", " + String(data.count) + " bytes"
                        + (failure.isEmpty ? "" : ", failureType " + failure), .download)

            // A 502 from Apple's edge arrives as a short HTML or plain-text
            // body with no failureType, so "no failureType and some bytes" is
            // not success -- it is a gateway error that reads like a plist-shaped
            // answer to anything that does not check the status. Require 200.
            if failure.isEmpty && http.statusCode == 200 && !data.isEmpty {
                return plist
            }
            if !failure.isEmpty {
                rejected = (failure, plist["customerMessage"] as? String ?? "")
            } else if http.statusCode != 200 {
                // Kept so the caller falls back to the classic endpoint with a
                // status in hand rather than an empty dictionary.
                rejected = ("http" + String(http.statusCode),
                            "ent/download returned " + String(http.statusCode))
            }
        }

        if !rejected.failure.isEmpty {
            throw StoreError.failureType(rejected.failure, rejected.message)
        }
        throw StoreError.httpError(lastStatus, "ent/download returned an empty body")
    }

    private func classicDownload(appId: String,
                                     externalVersionId: String?,
                                     guid: String,
                                     account: Account,
                                     bag: StoreBag,
                                     signer: SAPSigner) async throws -> [String: Any] {
        // The classic store endpoint, not the ent/download one in the bag.
        //
        // ipatool's downloadProductRequest (appstore_download_product.go:268)
        // posts to buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/
        // volumeStoreDownloadProduct with only iCloud-DSID and X-Dsid, no
        // X-Token, no store-front, and no signature. ent/download is a separate
        // newer path that ipatool only takes when it has a kbsync generator.
        // This app has one now, so ent/download is tried first and this is the
        // fallback for apps it will not serve.
        let podPrefix = account.pod.isEmpty ? "" : "p" + account.pod + "-"
        let endpoint = "https://" + podPrefix
            + "buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/volumeStoreDownloadProduct"
        AppLog.info("requesting download for " + appId + " from " + endpoint, .download)

        guard var components = URLComponents(url: try Self.trustedEndpoint(endpoint),
                                             resolvingAgainstBaseURL: false) else {
            throw StoreError.untrustedEndpoint(endpoint)
        }
        components.queryItems = [URLQueryItem(name: "guid", value: guid)]

        var payload: [String: Any] = [
            "creditDisplay": "",
            "guid": guid,
            "salableAdamId": Int64(appId) ?? 0,
            "serialNumber": "0",
        ]
        if let externalVersionId {
            payload["externalVersionId"] = externalVersionId
        }
        let body = try PropertyListSerialization.data(
            fromPropertyList: payload, format: .xml, options: 0)

        // Five header combinations, all tried in one pass.
        //
        // DSID alone answered "sign in required", and adding both X-Token and
        // X-Apple-Store-Front at once answered an empty 400. Two variables, one
        // build, no way to tell which caused it -- so the whole matrix is tried
        // here and the log names the one Apple accepts. That is cheaper than one
        // build per guess, which is how the last several rounds went.
        // Store-front is gone: it produced an empty 400 in every combination.
        // What is left is which credential goes in X-Token. authenticate returns
        // two, and the store calls the 52 character one a bad password token, so
        // the 32 character clearToken gets a turn as well.
        // One attempt. The five-way credential matrix is gone: every
        // combination returned the same 2042, so the credential was never the
        // variable. The variable this round is the Cookie header, which this
        // request has never sent -- only iCloud-DSID, X-Dsid and X-Token, none of
        // which carry a session.
        let attempts: [(label: String, token: String, signed: Bool)] = [
            ("cookie+passwordToken", account.passwordToken, false),
        ]

        // Printed once, because a zero-length token silently turns every
        // "token" attempt into a bare one: the two then return byte-identical
        // bodies and the comparison says nothing.
        AppLog.info("download session: passwordToken " + String(account.passwordToken.count)
                    + " chars, clearToken " + String(account.clearToken.count)
                    + " chars, dsid " + Self.masked(account.dsid)
                    + ", pod " + (account.pod.isEmpty ? "none" : account.pod), .download)

        // The classic endpoint authenticates a *session*, and a session is
        // cookies. ipatool's download client has a cookie jar for exactly this
        // reason. If nothing is stored for the store domain then no token will
        // help, so the names are printed -- names only, never values.
        let cookies = (session.configuration.httpCookieStorage?.cookies ?? [])
            .filter { $0.domain.contains("itunes.apple.com") }
        AppLog.info("store cookies: "
                    + (cookies.isEmpty
                       ? "none"
                       : cookies.map { $0.name }.joined(separator: ", ")), .download)
        // The cookie jar is empty either way, so the number that matters is the
        // replay header captured from Set-Cookie by hand.
        // Copied to locals: AppLog's message is an escaping autoclosure, and a
        // bare property reference inside one needs explicit self.
        let replayHeaderLength = capturedCookieHeader.count
        let replayValueCount = capturedCookieValues.count
        AppLog.info("replayed cookie header: "
                    + String(replayHeaderLength) + " chars, "
                    + String(replayValueCount) + " values", .download)

        var licenceFailure: (String, String)?
        var lastError: Error = StoreError.failureType("download", "every attempt failed")

        for attempt in attempts {
            var request = URLRequest(url: components.url!)
            request.httpMethod = "POST"
            request.setValue("application/x-apple-plist", forHTTPHeaderField: "Content-Type")
            request.setValue(account.dsid, forHTTPHeaderField: "iCloud-DSID")
            request.setValue(account.dsid, forHTTPHeaderField: "X-Dsid")
            if !attempt.token.isEmpty {
                request.setValue(attempt.token, forHTTPHeaderField: "X-Token")
            }
            // The session Apple actually checks. authenticate hands back
            // mz_at_ssl-<dsid>, X-Dsid, X-Token, wosid and session-store-id as
            // Set-Cookie; URLSession stores none of them for this domain, so
            // they are captured by hand and replayed here. Without this the
            // request carries three identifiers and no session, which is what
            // 2042 AuthTokenResumeFreeBuy describes.
            if !capturedCookieHeader.isEmpty {
                request.setValue(capturedCookieHeader, forHTTPHeaderField: "Cookie")
            }
            request.httpBody = body

            let responseData: Data
            let status: Int
            if attempt.signed {
                let (d, http) = try await signedRequest(request, signer: signer, redirects: 4)
                responseData = d
                status = http.statusCode
            } else {
                let (d, r) = try await session.data(for: request)
                responseData = d
                status = (r as? HTTPURLResponse)?.statusCode ?? -1
            }

            let preview = String(data: responseData.prefix(500), encoding: .utf8) ?? "<binary>"
            AppLog.info("download attempt [" + attempt.label + "] HTTP " + String(status)
                        + ", " + String(responseData.count) + " bytes", .download)
            if !preview.isEmpty {
                AppLog.info("  body: " + preview, .download)
            }

            guard status == 200 else {
                lastError = StoreError.failureType("http", "HTTP " + String(status))
                continue
            }

            let plist = (try? PropertyListSerialization.propertyList(
                from: responseData, options: [], format: nil)) as? [String: Any] ?? [:]
            let failure = plist["failureType"] as? String ?? ""
            let message = plist["customerMessage"] as? String ?? ""

            if failure.isEmpty && plist["songList"] != nil {
                AppLog.info("download attempt [" + attempt.label + "] returned a songList",
                            .download)
                return plist
            }
            // 2042 is "sign in required": Apple wants a live session, not a
            // licence. The two look alike in the UI, so name it in the log.
            let metrics = plist["metrics"] as? [String: Any] ?? [:]
            let code = metrics["messageCode"] as? String ?? ""
            if code == "2042" {
                AppLog.error("attempt [" + attempt.label + "] needs a fresh sign-in ("
                             + code + ", "
                             + (metrics["dialogId"] as? String ?? "") + ")", .download)
            }
            if failure == "9610" { licenceFailure = (failure, message) }
            lastError = StoreError.failureType(failure.isEmpty ? "download" : failure, message)
        }

        // A licence error from the endpoint Apple actually serves is worth
        // acting on; anything else is just the last thing that went wrong.
        if let (failure, message) = licenceFailure {
            throw StoreError.failureType(failure, message)
        }
        throw lastError
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
            captureCookies(from: http)
            if http.statusCode == 403 {
                let hadSignature = signed.value(forHTTPHeaderField: "X-Apple-ActionSignature")
                AppLog.error("403 from " + (signed.url?.host ?? "?")
                             + ", signature attached: " + String(hadSignature != nil)
                             + ", signature length: " + String(hadSignature?.count ?? 0)
                             + ", body length: " + String(body.count), .network)
                // Apple puts the reason in the body. Without it a 403 is just
                // a number, and the difference between "bad signature",
                // "wrong endpoint" and "account locked" is the whole answer.
                // Both lines used to carry whatever Apple sent. The body is
                // worth reading; the headers are not -- a 403 is routine and
                // URLSession is configured not to swallow Set-Cookie, so this
                // wrote live session cookies into a log the user can share.
                let text = String(data: data, encoding: .utf8)
                    ?? "<" + String(data.count) + " binary bytes>"
                AppLog.error("403 body (" + String(data.count) + " bytes, first 400): "
                             + String(text.prefix(400)), .network)
                AppLog.error("403 headers: " + Self.redactedHeaders(http.allHeaderFields),
                             .network)
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
            // at the top of the loop over the new body. A header that carries a
            // credential is dropped as well when the redirect leaves the host
            // that issued it -- the store answers some requests with a Location
            // on another pod, and this loop used to follow it with the cookie
            // and the account's token attached.
            let sameHost = next.host?.lowercased() == signed.url?.host?.lowercased()
            for (key, value) in signed.allHTTPHeaderFields ?? [:] where key != "X-Apple-ActionSignature" {
                if !sameHost, Self.isCredentialHeader(key) {
                    AppLog.info("redirect to a different host; dropping " + key, .network)

                    continue
                }
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
        let resolved: URL?

        if let absolute = URL(string: location), absolute.scheme != nil {
            resolved = absolute
        } else if let base {
            resolved = URL(string: location, relativeTo: base)?.absoluteURL
        } else {
            resolved = nil
        }

        // Downgrading to http would send the body and whatever headers survived
        // in clear text. Refusing leaves the caller with the 3xx, which is a
        // visible failure rather than a silent one.
        guard let resolved, resolved.scheme?.lowercased() == "https" else {
            AppLog.warn("refusing redirect to non-https location "
                        + location + " from " + (base?.absoluteString ?? "?"), .network)

            return nil
        }

        return resolved
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
