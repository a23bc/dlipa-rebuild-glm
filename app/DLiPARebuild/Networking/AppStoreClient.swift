import Foundation

/// Talks to the App Store private API.
///
/// Two things are mandatory for Apple to accept a request today, both proven by
/// experiment (see SIGNATURE_EXPERIMENT.md):
///
/// 1. The `X-Apple-ActionSignature` header over the exact body bytes.
/// 2. A trailing slash on the authenticate URL. Without it Apple answers 204
///    with an empty body and never looks at the request.
/// Why an `ent/download` request is being made.
///
/// `licence` means the answer is a package the account keeps, so the ownership
/// question is worth asking before the guest opens and the sinfs and metadata in
/// the response are worth storing -- the patch step reads them back. `metadata`
/// means the answer is a field inside the response: a version string, or the
/// identifiers of every version. Neither question is asked and nothing is
/// written in that case, because a version list was measured buying twenty
/// licences and overwriting the sinf slot twenty times while reading strings.
enum RequestPurpose: String {
    case licence
    case metadata
}

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

    /// The UA every other store request carries.
    ///
    /// internal/store/backend.go injects this whenever a request arrives without
    /// a User-Agent, so it is what the reference implementation sends on the
    /// classic download. Ours went out as whatever URLSession stamps on it
    /// (DLiPARebuild/… CFNetwork/…), which is a client Apple has never seen.
    /// The purchase operation is the one exception upstream: it uses 2.18.
    static let storeUserAgent =
        "Configurator/2.17 (Macintosh; OS X 15.2; 24C5089c) AppleWebKit/0620.1.16.11.6"

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
        restoreCookieJar()
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
        clearPersistedCookieJar()
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
        // A sign-in starts from an empty jar. The launch restores the previous
        // account's cookies, and signing in the second account on top of them left
        // that account's X-Token and DSID in the values this call captures -- the new
        // session was minted against the old one and every download through it failed
        // in the guest's request setup.
        //
        // Only the cookie state is dropped: the pod routing belongs to the 2FA retry,
        // and resetSession() would clear it between the two attempts.
        clearPersistedCookieJar()
        capturedCookieHeader = ""
        capturedCookieValues = [:]

        // The pod belongs to the account that was signed in before. Carrying it into a
        // different account's sign-in routes the request to that region's host: the
        // second account's session then reports the first account's storefront, and
        // every lookup for an app in the second account's own store comes back empty.
        //
        // Only on the first attempt: the 2FA retry has to reach the same pod the code
        // was challenged from.
        if attempt == 1 {
            authenticationPod = nil
        }

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
                // Recomputed on every try, and checked because this request
                // carries the Apple ID password. Hoisting it out of the loop
                // (which a previous change did) pinned every retry to the
                // generic endpoint while endpointNow was following the pod the
                // last attempt was redirected to -- turning a recoverable 403
                // into a failed sign-in.
                var attemptRequest = URLRequest(url: try Self.trustedEndpoint(endpointNow))
                attemptRequest.httpMethod = "POST"
                attemptRequest.setValue("application/x-www-form-urlencoded",
                                        forHTTPHeaderField: "Content-Type")
                attemptRequest.setValue(Self.bagUserAgent, forHTTPHeaderField: "User-Agent")
                attemptRequest.httpBody = body

                // What actually goes out, header by header. Apple routes a sign-in to
                // a regional pod, and a value in here is the only thing that can carry
                // the previous account's region into this one.
                let described = Self.describeRequestHeaders(attemptRequest)
                AppLog.info("authenticate request to " + attemptRequest.url!.absoluteString
                            + " headers: " + described, .auth)

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

        // This response is the only place the full session exists. Save it
        // against the DSID before handing the account back, because the jar is
        // reset the moment anything else is signed in, and a relaunch restores
        // the account without a sign-in to rebuild these cookies.
        saveCookieSnapshot(forDSID: dsid)

        // An empty cookie is not a token. Apple sets X-Token with an empty value
        // on some responses, and `?? passwordToken` never fires for a key that
        // exists: the account was saved with a zero-length session token, and the
        // buy then went out with no X-Token header at all -- which is what the
        // store answered with 2083 "sign in".
        let capturedSession = capturedCookieValues["X-Token"] ?? ""

        // Three credentials and their sizes, because the account was found
        // carrying a zero-length session token and this is the only place that
        // can say whether the cookie arrived empty or never arrived.
        AppLog.info("authenticate tokens: passwordToken " + String(passwordToken.count)
                    + ", clearToken " + String(clearToken.count)
                    + ", cookie X-Token " + String(capturedSession.count), .auth)

        return Account(
            email: accountInfo["appleId"] as? String ?? email,
            passwordToken: passwordToken,
            sessionToken: capturedSession.isEmpty ? passwordToken : capturedSession,
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

    /// The marketing version of one build, e.g. "14.30.1".
    ///
    /// The version list only carries identifiers, so the label behind each row has
    /// to be fetched: one signed download-product request per id, which is cheap --
    /// it reads songList metadata and never touches the encoder.
    func versionString(appId: String,
                       externalVersionId: String,
                       guid: String,
                       account: Account,
                       bag: StoreBag,
                       signer: SAPSigner) async throws -> String? {
        let plist = try await downloadProduct(appId: appId,
                                              externalVersionId: externalVersionId,
                                              guid: guid,
                                              account: account,
                                              bag: bag,
                                              signer: signer,
                                              purpose: .metadata)

        let songs = plist["songList"] as? [[String: Any]]
        let metadata = songs?.first?["metadata"] as? [String: Any]

        if let short = metadata?["bundleShortVersionString"] as? String, !short.isEmpty {
            return short
        }

        return nil
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
            guid: guid, account: account, bag: bag, signer: signer,
            purpose: .metadata)

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

    /// The cookie header the classic path replays, for callers that need the
    /// same session elsewhere. downloaddispatch answers 401 to a request that
    /// carries the token but not the session's cookies.
    var sessionCookieHeader: String { capturedCookieHeader }
    private var capturedCookieValues: [String: String] = [:]

    /// The jar has to outlive the process.
    ///
    /// The account and its tokens are restored from defaults at launch, but the
    /// cookies were not, so the first download after a restart replayed one
    /// meaningless cookie and Apple answered 2042 "sign in". A sign-in hands
    /// over mz_at_ssl-<dsid>, wosid, session-store-id and the rest; without them
    /// there is no session, however valid the token is.
    ///
    /// It lives in the same defaults as the tokens, which is not a strong place
    /// to keep a credential -- but separating them would put a session cookie in
    /// a safer store than the token it accompanies, and that is not a
    /// distinction worth making.
    private static let cookieJarHeaderKey = "com.a23bc.dliparebuild.cookieJar.header"
    private static let cookieJarValuesKey = "com.a23bc.dliparebuild.cookieJar.values"

    private func persistCookieJar() {
        let defaults = UserDefaults.standard
        defaults.set(capturedCookieHeader, forKey: Self.cookieJarHeaderKey)
        defaults.set(capturedCookieValues, forKey: Self.cookieJarValuesKey)
    }

    private func restoreCookieJar() {
        let defaults = UserDefaults.standard
        guard let header = defaults.string(forKey: Self.cookieJarHeaderKey),
              !header.isEmpty else {
            return
        }
        capturedCookieHeader = header
        capturedCookieValues = defaults.dictionary(forKey: Self.cookieJarValuesKey) as? [String: String] ?? [:]
        mirror("restored " + String(capturedCookieValues.count) + " cookies")
        // A local because AppLog's message is an escaping autoclosure, and a
        // property reference inside one needs explicit self.
        let restored = capturedCookieValues.count
        AppLog.info("restored " + String(restored)
                    + " cookies from the previous launch", .network)
    }

    private func clearPersistedCookieJar() {
        let defaults = UserDefaults.standard
        defaults.removeObject(forKey: Self.cookieJarHeaderKey)
        defaults.removeObject(forKey: Self.cookieJarValuesKey)
    }

    // MARK: - Per-account cookie snapshots

    /// One cookie of an account's store session, as it is written to disk.
    ///
    /// The whole record is kept, not only name and value: HTTPCookie needs a
    /// domain and a path to be rebuilt, and a cookie restored under the wrong
    /// domain is either invisible to the store or attached to the wrong host.
    private struct CookieSnapshotEntry: Codable {
        let name: String
        let value: String
        let domain: String
        let path: String
        let expires: Date?
        let secure: Bool
    }

    private static let cookieSnapshotFolder = "cookies"

    private static func cookieSnapshotDirectory() -> URL? {
        guard let base = FileManager.default.urls(for: .applicationSupportDirectory,
                                                  in: .userDomainMask).first else {
            return nil
        }
        return base.appendingPathComponent(cookieSnapshotFolder, isDirectory: true)
    }

    /// `<application support>/cookies/<dsid>.json`.
    ///
    /// The DSID is numeric; anything else is dropped rather than escaped so a
    /// malformed one cannot name a path outside the folder.
    private static func cookieSnapshotURL(forDSID dsid: String) -> URL? {
        let name = dsid.filter { $0.isLetter || $0.isNumber }
        guard !name.isEmpty, let directory = cookieSnapshotDirectory() else { return nil }
        return directory.appendingPathComponent(name + ".json", isDirectory: false)
    }

    /// The store cookies the session's jar holds right now.
    private func storeCookies() -> [HTTPCookie] {
        guard let storage = session.configuration.httpCookieStorage else { return [] }
        return (storage.cookies ?? []).filter { $0.domain.contains("itunes.apple.com") }
    }

    /// Writes the whole store session for one DSID.
    ///
    /// A sign-in is the only moment the complete set exists -- eighteen cookies
    /// on device -- and the handful that survive a relaunch is not enough for
    /// the guest, which refuses a request carrying only X-Dsid and X-Token. The
    /// account's own DSID names the file, because these cookies are worthless
    /// to any other account.
    func saveCookieSnapshot(forDSID dsid: String, quiet: Bool = false) {
        // httpShouldSetCookies is off for this session, so Set-Cookie never reaches
        // HTTPCookieStorage: the jar is empty even when the response set nineteen
        // cookies. The hand-copied values are the session; saving the jar saved
        // nothing, which is why the log said "store cookies: none" beside them.
        var entries = storeCookies().map {
            CookieSnapshotEntry(name: $0.name, value: $0.value, domain: $0.domain,
                                path: $0.path, expires: $0.expiresDate,
                                secure: $0.isSecure)
        }

        if entries.isEmpty {
            entries = capturedCookieValues.map {
                CookieSnapshotEntry(name: $0.key, value: $0.value,
                                    domain: "itunes.apple.com", path: "/",
                                    expires: nil, secure: true)
            }
        }

        guard !entries.isEmpty else {
            AppLog.warn("no store cookies to save for this account", .network)
            return
        }

        guard let url = Self.cookieSnapshotURL(forDSID: dsid) else { return }

        do {
            let data = try JSONEncoder().encode(entries)
            try FileManager.default.createDirectory(at: url.deletingLastPathComponent(),
                                                    withIntermediateDirectories: true)
            try data.write(to: url, options: .atomic)
            // Count only: every value in here is a session credential. Silent on
            // the refresh path, which runs after every store response.
            if !quiet {
                AppLog.info("saved " + String(entries.count) + " cookies for this account",
                            .network)
            }
        } catch {
            AppLog.warn("could not save the cookie snapshot: " + error.localizedDescription,
                        .network)
        }
    }

    /// Forgets one account's cookies when the account itself is gone.
    ///
    /// The file holds a live session; leaving it behind after the account is removed
    /// keeps a credential that nothing can revoke from the app's side.
    func deleteCookieSnapshot(forDSID dsid: String) {
        guard let url = Self.cookieSnapshotURL(forDSID: dsid) else { return }

        guard FileManager.default.fileExists(atPath: url.path) else { return }

        do {
            try FileManager.default.removeItem(at: url)
        } catch {
            AppLog.warn("could not delete the cookie snapshot: " + error.localizedDescription,
                        .network)
        }
    }

    /// Puts one account's cookies back into the jar.
    ///
    /// Whatever the jar holds for itunes.apple.com goes first: a sign-in, a
    /// different account, or the previous launch all leave cookies there, and
    /// two accounts' cookies replayed together is what made the second one
    /// fail.
    func restoreCookies(forDSID dsid: String) {
        guard let url = Self.cookieSnapshotURL(forDSID: dsid) else { return }
        guard FileManager.default.fileExists(atPath: url.path) else {
            // The normal case for an account signed in by a build that had no
            // snapshots. The next sign-in writes one.
            AppLog.info("no saved cookies for this account yet", .network)
            return
        }

        let entries: [CookieSnapshotEntry]
        do {
            let data = try Data(contentsOf: url)
            entries = try JSONDecoder().decode([CookieSnapshotEntry].self, from: data)
        } catch {
            AppLog.warn("could not read the cookie snapshot: " + error.localizedDescription,
                        .network)
            return
        }

        guard let storage = session.configuration.httpCookieStorage else { return }
        let stale = (storage.cookies ?? [])
            .filter { $0.domain.contains("itunes.apple.com") }
        for cookie in stale { storage.deleteCookie(cookie) }

        var installed = 0
        var pairs: [String] = []
        var values: [String: String] = [:]
        for entry in entries {
            guard let cookie = Self.cookie(from: entry) else { continue }
            storage.setCookie(cookie)
            installed += 1
            pairs.append(entry.name + "=" + entry.value)
            values[entry.name] = entry.value
        }

        // The guest never reads HTTPCookieStorage: entDownload replays this
        // header, so restoring the jar alone would restore a session nothing
        // uses. Built from the snapshot instead of merged into the existing
        // header, so no cookie from another account can survive here.
        capturedCookieHeader = pairs.joined(separator: "; ")
        capturedCookieValues = values

        AppLog.info("restored " + String(installed) + " cookies for this account", .network)
    }

    private static func cookie(from entry: CookieSnapshotEntry) -> HTTPCookie? {
        var properties: [HTTPCookiePropertyKey: Any] = [
            .name: entry.name,
            .value: entry.value,
            .domain: entry.domain,
            .path: entry.path.isEmpty ? "/" : entry.path,
        ]
        if let expires = entry.expires {
            properties[.expires] = expires
        }
        if entry.secure {
            properties[.secure] = "TRUE"
        }
        return HTTPCookie(properties: properties)
    }

    /// POSTs without the SAP signature.
    ///
    /// Neither appstore_purchase.go nor appstore_kbsync.go signs these: the
    /// store is expected to take them on the session alone. Ours attach
    /// X-Apple-ActionSignature to both, and both come back with errors the store
    /// would not otherwise produce -- an empty-bodied 500 from ent/download and
    /// MZCommerce.SystemError from buyProduct.
    private func sendUnsigned(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw StoreError.httpError(-1, "not an HTTP response")
        }

        captureCookies(from: http)
        AppLog.info("unsigned request to " + (request.url?.absoluteString ?? "?")
                    + " returned " + String(http.statusCode)
                    + ", body " + String(data.count) + " bytes", .network)

        return (data, http)
    }

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

        persistCookieJar()

        // Keep the per-account snapshot as fresh as the live jar.
        //
        // It used to be written once, at sign-in, and never again: every relaunch
        // then restored the session as it stood at sign-in and discarded whatever
        // the store had rotated since. That is how a credential that bought an app
        // one minute after signing in came back as 2034 ExpiredPasswordToken half
        // an hour later. X-Dsid is the account these cookies belong to.
        if let dsid = capturedCookieValues["X-Dsid"], !dsid.isEmpty {
            saveCookieSnapshot(forDSID: dsid, quiet: true)
        }
    }

    /// What goes out on a request, header by header, through the same redaction
    /// the response dumps use.
    ///
    /// This call site used to have its own rule -- the first 24 characters of
    /// every value -- which was written when Content-Type and User-Agent were the
    /// only headers a sign-in carried. A request in this class can carry a session,
    /// and 24 characters of a cookie is a credential fragment in the log that the
    /// diagnostics tab invites the person to share.
    private static func describeRequestHeaders(_ request: URLRequest) -> String {
        let headers: [AnyHashable: Any] = request.allHTTPHeaderFields ?? [:]

        return headers.isEmpty ? "none" : redactedHeaders(headers, cap: 24)
    }

    /// Header names with the values of anything carrying a credential replaced
    /// by its length. Names and lengths still say what the response contained.
    ///
    /// `cap` shortens the values that are *not* credentials, for the callers that
    /// want a compact line -- a User-Agent is 60-some characters and no dump needs
    /// all of it. The list is matched on the lower-cased name because the store
    /// spells the same field three ways across the flows (`X-Dsid`,
    /// `iCloud-DSID`, `X-Apple-DSID`), and the second of those is the one this
    /// client itself sets on the buy and download requests -- the earlier list
    /// covered `x-icloud-dsid`, which no header ever matches.
    private static func redactedHeaders(_ headers: [AnyHashable: Any], cap: Int = 0) -> String {
        let sensitive = ["set-cookie", "cookie", "x-token", "authorization",
                         "x-apple-dsid", "icloud-dsid", "x-dsid"]
        let parts: [String] = headers.keys.map { key in
            let name = String(describing: key)
            let lower = name.lowercased()
            let value = String(describing: headers[key] ?? "")
            if sensitive.contains(where: { lower.contains($0) }) {
                return name + "=<redacted " + String(value.count) + " chars>"
            }
            if cap > 0, value.count > cap {
                return name + "=" + String(value.prefix(cap))
            }
            return name + "=" + value
        }
        return parts.sorted().joined(separator: ", ")
    }

    /// The fields that answer "which failure, and where does Apple want the next
    /// request", without the body they live in.
    ///
    /// Three call sites used to print whole responses. Their reason was a real
    /// bug: a 500-byte cut dropped `actionUrl`, which sits below that much text
    /// and is the only field naming the continuation. Reading the fields keeps
    /// that lesson and stops a version list -- which asks once per visible row,
    /// and whose classic fallback runs six attempts each time -- from writing tens
    /// of thousands of lines of near-identical plist into a log that is then copied
    /// and re-rendered on every line. The 403 case is the same question, and that
    /// body can name the account, the request and the device, so it too is reduced
    /// to these keys.
    ///
    /// Scanned as text, not parsed: these answers are shaped for a browser and a
    /// 403 page is not a plist. Values are capped where they are long, and
    /// `songList` is reported as present rather than printed -- it is the 18 kB
    /// half of a download response.
    private static func responseDetail(from data: Data) -> String {
        guard let text = String(data: data, encoding: .utf8) else {
            return "<" + String(data.count) + " binary bytes>"
        }

        let keys = ["failureType", "customerMessage", "message", "dialogId", "messageCode", "actionUrl"]
        var parts: [String] = []

        for key in keys {
            guard let keyRange = text.range(of: "<key>" + key + "</key>") else { continue }

            let rest = text[keyRange.upperBound...]
            guard let open = rest.range(of: "<string>"),
                  let close = rest.range(of: "</string>", range: open.upperBound..<rest.endIndex) else {
                continue
            }

            parts.append(key + "=" + String(rest[open.upperBound..<close.lowerBound].prefix(120)))
        }

        if text.contains("<key>songList</key>") {
            parts.append("songList")
        }

        return parts.isEmpty
            ? "<" + String(data.count) + " bytes, no answer fields>"
            : parts.joined(separator: " ")
    }

    /// One line to stderr, for the file that can be copied off the device.
    ///
    /// Deliberately not a global AppLog mirror: the black-box recorder replays
    /// the previous launch's stderr *through AppLog*, so mirroring every entry
    /// there fed the recorder its own output, doubled the file on every launch
    /// and killed the app at start -- 17 MB and 41k lines of "prev.stderr |".
    /// This writes only what is named here.
    private func mirror(_ message: String) {
        fputs("[DLiPA] " + message + "\n", stderr)
    }

    /// Moves an endpoint onto one host, keeping path and query.
    ///
    /// Nothing here invents a path: Apple's bag names the endpoint, and the host
    /// only decides which pod serves it. A bare path is put on the host as
    /// given; an endpoint already on that host is returned untouched.
    static func moved(_ endpoint: String, onto host: String) -> String {
        guard var components = URLComponents(string: endpoint),
              components.host != nil else {
            return "https://" + host + endpoint
        }

        if components.host == host {
            return endpoint
        }

        components.host = host
        components.scheme = "https"

        return components.url?.absoluteString ?? ("https://" + host + endpoint)
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
                    AppLog.info(tag + " HTTP " + String(status) + ", "
                                + String(data.count) + " bytes, "
                                + Self.responseDetail(from: data), .auth)
                    let parsed = (try? PropertyListSerialization.propertyList(
                        from: data, options: [], format: nil)) as? [String: Any] ?? [:]
                    let code = (parsed["metrics"] as? [String: Any])?["messageCode"] as? String
                    if (200..<300).contains(status) && code == nil
                        && (parsed["failureType"] as? String ?? "").isEmpty {
                        AppLog.info(tag + " accepted; the machine is authorised", .auth)
                        return true
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

    /// One shape of the buy request: where it goes and which token it carries.
    ///
    /// The reference request (ipatool, pkg/appstore/appstore_purchase.go) is the
    /// right URL and the wrong credential: it sends acc.PasswordToken, and the
    /// store answered 2034 ExpiredPasswordToken for that on this account while
    /// accepting the mz_at0_fr cookie on the same request. The shape is kept as a
    /// value so the log can name which one answered.
    private struct LicenceShape {
        let label: String
        let url: URL
        let token: String
    }

    /// The fields of a buy response this client acts on.
    private struct LicenceReply {
        let status: Int
        let failure: String
        let message: String
        let docType: String
        let jingleStatus: Int
    }

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
    /// purchase that had actually worked. The same 500 is also what a host that
    /// never accepted the request answers, so it is believed here only when no
    /// shape confirms anything better.
    /// Called when the store retires the session's token (2034).
    ///
    /// The client cannot renew a session by itself -- no password, no bag -- so
    /// the session layer signs in again and hands back the account that came of
    /// it. This is upstream's flow: `ErrPasswordTokenExpired` is answered with a
    /// fresh Login before the request is retried (cmd/download.go:55).
    var refreshAccount: (@Sendable (Account) async -> Account?)?

    /// Attaches a free licence for an app to the account, renewing the session
    /// once if the store says its token has been retired.
    func acquireLicense(appId: String,
                        guid: String,
                        account: Account,
                        bag: StoreBag,
                        signer: SAPSigner) async throws {
        do {
            try await purchaseLicence(appId: appId, guid: guid, account: account,
                                      bag: bag, signer: signer)
        } catch let error as StoreError {
            guard case .failureType(let type, _) = error,
                  type == "licence-session-expired",
                  let refresh = refreshAccount,
                  let fresh = await refresh(account) else {
                throw error
            }

            AppLog.info("licence: retrying with the account the new sign-in produced",
                        .download)
            try await purchaseLicence(appId: appId, guid: guid, account: fresh,
                                      bag: bag, signer: signer)
        }
    }

    /// The buy itself, in every shape the account's credentials allow.
    private func purchaseLicence(appId: String,
                        guid: String,
                        account: Account,
                        bag: StoreBag,
                        signer: SAPSigner) async throws {
        let shapes = licenceShapes(account: account, bag: bag)
        AppLog.info("buyProduct: " + String(shapes.count) + " shapes for " + appId
                    + " (storefront "
                    + (account.storefront.isEmpty ? "none" : account.storefront)
                    + ", pod " + (account.pod.isEmpty ? "none" : account.pod) + ")", .download)

        var lastError: Error?
        // Kept apart from lastError: a shape that was refused over its credential
        // is the actionable verdict, and the shapes after it answer something
        // vaguer that would otherwise hide it.
        var sessionExpired: Error?
        var sawFiveHundred = false
        nextShape: for shape in shapes {
            var reply: LicenceReply
            do {
                reply = try await sendBuy(shape: shape, pricing: "STDQ",
                                          appId: appId, guid: guid, account: account)
                // A gateway error is Apple's edge, not a verdict. It cost a whole
                // run once -- the reference shape answered 504, the two fallbacks
                // answered their usual SystemError, and the app reported "unable
                // to process your request" for a credential that had worked ten
                // minutes earlier.
                if Self.transientGatewayStatus.contains(reply.status) {
                    AppLog.warn("buyProduct " + shape.label + " answered HTTP "
                                + String(reply.status) + "; retrying once", .download)
                    try? await Task.sleep(nanoseconds: 1_500_000_000)
                    reply = try await sendBuy(shape: shape, pricing: "STDQ",
                                              appId: appId, guid: guid, account: account)
                }
                // STDQ is the normal pricing parameter; GAME is the Apple Arcade
                // one ipatool falls back to when the item reports as temporarily
                // unavailable.
                if reply.failure == "2059" {
                    try? await Task.sleep(nanoseconds: 2_000_000_000)
                    reply = try await sendBuy(shape: shape, pricing: "GAME",
                                              appId: appId, guid: guid, account: account)
                }
            } catch {
                // A request that never left says nothing about the shape.
                AppLog.warn("buyProduct " + shape.label + " could not be sent: "
                            + error.localizedDescription, .download)
                lastError = error
                continue nextShape
            }

            if reply.failure == "5002" {
                AppLog.info("licence already present", .download)
                return
            }
            if reply.failure == "2059" {
                lastError = StoreError.failureType(reply.failure, reply.message)
                continue nextShape
            }
            if !reply.failure.isEmpty {
                // A refusal that names the credential is about this shape, not
                // about the item: the account has already been refused with 2002
                // carrying the passwordToken while the session cookie was
                // accepted, so the next shape still deserves its turn. 2083 is
                // the same thing said differently -- MZCommerce.FamilyFreeProduct
                // AgeCheck, "sign in" -- and it is what the store answers when no
                // X-Token goes out at all. Every other code is the store's verdict
                // on the purchase itself.
                let aboutToken = ["signInRequired", "passwordTokenExpired",
                                  "deviceVerificationFailed", "2002", "2034", "2083"]
                    .contains(reply.failure)
                    || reply.message.lowercased().contains("password")

                AppLog.error("buyProduct " + shape.label + " failed: "
                             + reply.failure + " " + reply.message, .download)

                if !aboutToken {
                    throw Self.licenceFailure(reply.failure, reply.message)
                }

                let mapped = Self.licenceFailure(reply.failure, reply.message)
                if Self.sessionExpiredCodes.contains(reply.failure) {
                    sessionExpired = mapped
                }
                lastError = mapped
                continue nextShape
            }

            // The mapping ipatool relies on, and in its order: a body that names
            // a failure is read before the bare status is. 500 with nothing in it
            // is "the licence already exists" -- but it is also what a host that
            // never accepted the request answers, so this pass keeps probing and
            // believes it only if nothing else answers.
            if reply.status == 500 {
                AppLog.info("buyProduct " + shape.label + " answered 500 with no failure "
                            + "code; per ipatool that means the licence already exists",
                            .download)
                sawFiveHundred = true
                lastError = StoreError.failureType("licence-unconfirmed",
                                                   "HTTP 500 from " + shape.label)
                continue nextShape
            }

            // purchaseWithParams requires jingleDocType == "purchaseSuccess" and
            // status == 0, and treats anything else as a failure. An earlier check
            // here accepted an empty docType, so a 200 carrying
            // MZCommerce.SystemError and "Unable to process your request" was
            // reported as "licence granted" -- and the download then retried
            // against a licence that had never been issued.
            if reply.docType == "purchaseSuccess", reply.jingleStatus == 0 {
                AppLog.info("licence granted via " + shape.label, .download)
                return
            }

            let detail = reply.message.isEmpty ? "no purchaseSuccess in the response"
                                              : reply.message
            AppLog.error("buyProduct " + shape.label + " did not confirm the purchase: "
                         + detail, .download)
            lastError = StoreError.failureType("purchase", detail)
        }

        if let sessionExpired {
            throw sessionExpired
        }

        if sawFiveHundred {
            // Nothing confirmed the purchase, but a 500 is ipatool's "the licence
            // is already there". Returning lets the download be the judge instead
            // of failing a purchase that may well have gone through.
            AppLog.warn("no shape confirmed the purchase; a 500 says the licence exists",
                        .download)
            return
        }

        throw lastError ?? StoreError.failureType("purchase", "no purchase response")
    }

    /// Posts one buy request and reads the fields the store reports.
    ///
    /// The payload is field for field what appstore_purchase.go sends, and the
    /// User-Agent is the 2.18 one backend.go switches to for "purchase". Nothing
    /// is signed: the reference does not sign this call, and a signed copy of the
    /// same request was answered 400 on the device.
    ///
    /// A previous version swapped buyWithoutAuthorization for the 2042 dialog's
    /// hasBeenAuthedForBuy and added creditDisplay and serialNumber from the
    /// dialog's buyParams; the store answered 200 with MZCommerce.SystemError,
    /// "Unable to process your request". The dialog's buyParams describe a
    /// different operation than this endpoint takes.
    private func sendBuy(shape: LicenceShape,
                         pricing: String,
                         appId: String,
                         guid: String,
                         account: Account) async throws -> LicenceReply {
        var request = URLRequest(url: shape.url)
        request.httpMethod = "POST"
        request.setValue("application/x-apple-plist", forHTTPHeaderField: "Content-Type")
        // The purchase operation is the one place upstream departs from the
        // default agent: backend.go switches to 2.18 for "purchase".
        request.setValue(Self.downloadUserAgent, forHTTPHeaderField: "User-Agent")
        request.setValue(account.dsid, forHTTPHeaderField: "iCloud-DSID")
        request.setValue(account.dsid, forHTTPHeaderField: "X-Dsid")
        request.setValue(account.storefront, forHTTPHeaderField: "X-Apple-Store-Front")
        // An empty token is a shape of its own: the request then relies on the
        // session cookie alone, which is what the download endpoint ended up
        // needing.
        if !shape.token.isEmpty {
            request.setValue(shape.token, forHTTPHeaderField: "X-Token")
        }
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
        request.httpBody = try PropertyListSerialization.data(fromPropertyList: payload,
                                                              format: .xml, options: 0)

        let (data, response) = try await sendUnsigned(request)
        let status = response.statusCode
        AppLog.info("buyProduct " + shape.label + " " + pricing + " -> HTTP "
                    + String(status) + ", " + String(data.count) + " bytes, token "
                    + String(shape.token.count) + " chars", .download)
        if !data.isEmpty {
            AppLog.info("buyProduct " + shape.label + " " + pricing + " -> "
                        + Self.responseDetail(from: data), .download)
        }

        let plist = (try? PropertyListSerialization.propertyList(
            from: data, options: [], format: nil)) as? [String: Any] ?? [:]
        return LicenceReply(status: status,
                            failure: plist["failureType"] as? String ?? "",
                            message: plist["customerMessage"] as? String ?? "",
                            docType: plist["jingleDocType"] as? String ?? "",
                            jingleStatus: plist["status"] as? Int ?? 0)
    }

    /// The four things the store reports through one field, named apart: sign in
    /// again, buy a subscription, wait, or read the message. Passing the raw code
    /// up made every one of them look like the same failure.
    private static func licenceFailure(_ failure: String, _ message: String) -> Error {
        let lower = message.lowercased()

        // The numeric codes are the ones the store actually sends: ipatool maps
        // 2034 (ExpiredPasswordToken), 2042 (SignInRequired) and 2002
        // (BadPasswordToken) to the same "sign in again" outcome, and the message
        // is localised, so matching on its English word never fired here.
        if ["signInRequired", "passwordTokenExpired", "deviceVerificationFailed",
            "2034", "2042", "2002"].contains(failure) || lower.contains("password") {
            return StoreError.failureType("licence-session-expired",
                                          message.isEmpty ? "sign in again" : message)
        }

        if lower.contains("subscription") || lower.contains("apple arcade") {
            return StoreError.failureType("licence-subscription",
                                          message.isEmpty ? "subscription required" : message)
        }

        if failure == "temporarilyUnavailable" {
            return StoreError.failureType("licence-unavailable",
                                          message.isEmpty ? "temporarily unavailable" : message)
        }

        return StoreError.failureType(failure, message)
    }

    /// The shape the store accepts, and two fallbacks for accounts that never
    /// captured the cookie it needs.
    ///
    /// One request settled this on the device (2026-11-06 04:53):
    ///
    ///     POST https://p47-buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/buyProduct
    ///     X-Token: the value of the mz_at0_fr-<dsid> cookie
    ///
    ///     -> jingleDocType purchaseSuccess, status 0
    ///
    /// It is conclusive rather than lucky because the other credentials were
    /// refused by the same request, each with its own code: mz_at_ssl-<dsid>
    /// answered 2002 MZCommerce.BadPasswordToken, the 52 character passwordToken
    /// answered 2034 ExpiredPasswordToken, and sending no header at all answered
    /// 2083 "sign in". The bag's MZBuy path answers MZCommerce.SystemError
    /// whatever it is given, which is why the reference path is the one used.
    private func licenceShapes(account: Account, bag: StoreBag) -> [LicenceShape] {
        let podHost = (account.pod.isEmpty ? "" : "p" + account.pod + "-")
            + "buy.itunes.apple.com"
        let bagPath = Self.moved(bag.buyProduct
            ?? ("https://buy.itunes.apple.com/WebObjects/MZBuy.woa/wa/buyProduct"),
            onto: podHost)
        let referencePath = Self.moved("/WebObjects/MZFinance.woa/wa/buyProduct",
                                       onto: podHost)

        // The account's own store cookie, which is the credential the store
        // actually checks for a buy. Apple also sets an unscoped `mz_at0_fr`, and
        // an account signed in before the jar was captured per-DSID may only have
        // that one. Lengths only -- this is a session credential.
        let frontendToken = capturedCookieValues["mz_at0_fr-" + account.dsid]
            ?? capturedCookieValues["mz_at0_fr"] ?? ""

        AppLog.info("buyProduct credential: mz_at0_fr " + String(frontendToken.count)
                    + " chars, fallback sessionToken "
                    + String(account.sessionToken.count)
                    + ", dsid " + Self.masked(account.dsid), .download)

        let candidates: [(label: String, endpoint: String, token: String)] = [
            ("reference/mzAt0Fr", referencePath, frontendToken),
            ("bag/mzAt0Fr", bagPath, frontendToken),
            ("bag/sessionToken", bagPath, account.sessionToken),
        ]

        var shapes: [LicenceShape] = []
        var seen: Set<String> = []

        for candidate in candidates {
            // An empty credential is the shape that already measured 2083 "sign
            // in", no matter the path. Dropped here rather than deduped by
            // accident, which is how it slipped through once.
            guard !candidate.token.isEmpty,
                  let url = try? Self.trustedEndpoint(candidate.endpoint) else { continue }

            let key = url.absoluteString + "\u{0}" + candidate.token
            guard !seen.contains(key) else { continue }

            seen.insert(key)
            shapes.append(LicenceShape(label: candidate.label, url: url,
                                       token: candidate.token))
        }

        return shapes
    }

    /// The `ent/download` round trip, acquring a licence first if Apple says
    /// one is missing -- when the answer is something the account keeps.
    private func downloadProduct(appId: String,
                                 externalVersionId: String?,
                                 guid: String,
                                 account: Account,
                                 bag: StoreBag,
                                 signer: SAPSigner,
                                 purpose: RequestPurpose = .licence) async throws -> [String: Any] {
        // The licence gate, before the guest.
        //
        // ent/download needs the emulated Store runtime, and opening it costs
        // about a minute and a half of mapping on device. Discovering only after
        // that mapping that the account has no licence -- and then buying, which
        // is a plain request that answers in a second -- is what this removes:
        // the classic endpoint answers the ownership question in one request, so
        // the buy happens before the runtime is touched.
        //
        // The gate's own songList is dropped on a positive answer: ent/download
        // is the path the bridge has been measured on, and this check is about
        // the licence, not about which endpoint serves the file.
        // Skipped for a metadata read. The gate is six classic attempts and, in
        // this run, 1.9-6.4 s per call; the ownership of every row in a version
        // list is already settled by the list itself, and asking costs a second
        // and answers nothing. The download path keeps it.
        if purpose == .metadata {
            return try await downloadWithRetries(
                appId: appId, externalVersionId: externalVersionId, guid: guid,
                account: account, bag: bag, signer: signer,
                acquiredLicence: false, purpose: purpose)
        }

        let gateStart = Date()
        let missing = await licenceMissing(appId: appId,
                                           externalVersionId: externalVersionId,
                                           guid: guid, account: account,
                                           bag: bag, signer: signer)

        if missing == false {
            AppLog.info("licence gate: the account already owns this app ("
                        + Self.seconds(since: gateStart) + ")", .download)
        } else if missing == true {
            // Not bought here on purpose: the licence belongs to the person, and
            // the download button asks before anything is acquired. A download
            // that reaches this line without that consent stops here instead of
            // spending it.
            AppLog.info("licence gate: no licence after " + Self.seconds(since: gateStart)
                        + "; asking for one instead of buying it", .download)
            throw StoreError.failureType("licence-required",
                                         "This app needs a licence first")
        } else {
            // A gateway error, a transport failure, an answer this guard does not
            // know: none of them is a licence verdict, so ent/download decides.
            AppLog.info("licence gate: no verdict in " + Self.seconds(since: gateStart)
                        + "; leaving it to ent/download", .download)
        }

        return try await downloadWithRetries(
            appId: appId, externalVersionId: externalVersionId, guid: guid,
            account: account, bag: bag, signer: signer,
            acquiredLicence: false, purpose: purpose)
    }

    /// Whether the account owns the app, asked of the cheap endpoint.
    ///
    /// A songList means it does, 9610 and 2042 mean it does not, and anything
    /// else -- a gateway error, a transport failure -- is no verdict at all. The
    /// callers that can ask the person first (the download button) use this
    /// directly; the ones that cannot fall through to ent/download.
    func licenceMissing(appId: String,
                        externalVersionId: String?,
                        guid: String,
                        account: Account,
                        bag: StoreBag,
                        signer: SAPSigner) async -> Bool? {
        do {
            _ = try await classicDownload(appId: appId,
                                          externalVersionId: externalVersionId,
                                          guid: guid, account: account,
                                          bag: bag, signer: signer)
            return false
        } catch {
            guard let store = error as? StoreError,
                  case .failureType(let type, _) = store,
                  Self.licenceGapFailureTypes.contains(type) else {
                return nil
            }

            return true
        }
    }

    /// "12ms" or "1.4s", for the gate's two log lines.
    private static func seconds(since start: Date) -> String {
        let elapsed = Date().timeIntervalSince(start)

        return elapsed < 1
            ? String(Int(elapsed * 1000)) + "ms"
            : String(format: "%.1fs", elapsed)
    }

    /// The download itself, with the licence and blob retries.
    private func downloadWithRetries(appId: String,
                                     externalVersionId: String?,
                                     guid: String,
                                     account: Account,
                                     bag: StoreBag,
                                     signer: SAPSigner,
                                     acquiredLicence: Bool,
                                     purpose: RequestPurpose) async throws -> [String: Any] {
        var acquiredLicence = acquiredLicence
        var resumedBuy = false
        var discardedBlob = false

        while true {
            do {
                return try await downloadProductOnce(
                    appId: appId, externalVersionId: externalVersionId,
                    guid: guid, account: account, bag: bag, signer: signer,
                    purpose: purpose)
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

                // 2042 with kind=authorization and okButtonAction.kind=Buy is
                // not "sign in again": the dialog carries the buy it wants,
                // complete with buyParams and hasBeenAuthedForBuy=true. Doing
                // that buy is the resume Apple is offering, so it comes first
                // and the blob is left alone.
                if type == "2042", !resumedBuy {
                    resumedBuy = true
                    AppLog.info("download answered 2042; performing the buy the "
                                + "dialog asked for and retrying", .download)
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

    /// Apple's edge answers these when the request never reached a store pod.
    /// They say nothing about the credential, so the same request deserves one
    /// repeat before the next shape is tried.
    private static let transientGatewayStatus: Set<Int> = [502, 503, 504]

    /// The answer that means "this account has no licence for the app".
    ///
    /// Only 9610, "License not found". 2042 (MZCommerce.AuthTokenResumeFreeBuy)
    /// was in this set and cost a download that had just been paid for: the
    /// classic endpoint answers 2042 with a Buy dialog for an app whose licence
    /// exists, which is why this project stopped using it as the download path in
    /// the first place. A 2042 is the store asking for the buy, not a statement
    /// about ownership, so the gate leaves it to ent/download.
    private static let licenceGapFailureTypes: Set<String> = ["9610"]

    /// The answers that mean the session's token is no longer current. Upstream
    /// folds all of these into one outcome and signs in again before retrying.
    private static let sessionExpiredCodes: Set<String> = [
        "2034", "2042", "2002", "signInRequired", "passwordTokenExpired",
        "deviceVerificationFailed",
    ]

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
                                     signer: SAPSigner,
                                     purpose: RequestPurpose) async throws -> [String: Any] {
        if let ent = bag.volumeStoreDownloadProduct {
            do {
                return try await entDownload(appId: appId,
                                             externalVersionId: externalVersionId,
                                             guid: guid, account: account,
                                             endpoint: ent, signer: signer,
                                             purpose: purpose)
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

    /// ent/download, built and sent by the Store's own encoder.
    ///
    /// Everything this used to construct by hand -- the plist body, the content
    /// type override, the Configurator agent, the cookie replay -- now happens
    /// inside the bridge, because that is the only construction Apple's endpoint
    /// answered with 200. What comes back is the raw plist, parsed here so the
    /// callers keep reading the same keys.
    private func entDownload(appId: String,
                             externalVersionId: String?,
                             guid: String,
                             account: Account,
                             endpoint: String,
                             signer: SAPSigner,
                             purpose: RequestPurpose) async throws -> [String: Any] {
        guard let numericID = Int64(appId) else {
            throw StoreError.failureType("badAppID", "app id " + appId + " is not numeric")
        }

        // The bridge call blocks for as long as the guest runs -- minutes on
        // device -- so it cannot be made from the main actor. Locals first: the
        // closure below must not read properties off self.
        let dsid = account.dsid
        let token = account.passwordToken
        let storefront = account.storefront
        // The guest's request setup needs the session cookies, and the jar can be
        // nearly empty -- one cookie after an upgrade, where a fresh sign-in leaves
        // eighteen. The two that matter are the ones the account already carries, so
        // they are added when the jar does not have them.
        var cookieHeader = capturedCookieHeader

        if !cookieHeader.contains("X-Token=") {
            let essentials = "X-Dsid=" + dsid + "; X-Token=" + account.sessionToken

            cookieHeader = cookieHeader.isEmpty ? essentials : cookieHeader + "; " + essentials
        }

        let version = externalVersionId ?? ""

        // Utility, not userInitiated: the guest mapping saturates a core for about a
        // minute, and on a two core phone that is the difference between a stutter
        // and a screen that stops responding.
        let json = try await Task.detached(priority: .utility) {
            try signer.entDownload(dsid: dsid, token: token, storefront: storefront,
                                   endpoint: endpoint, cookieHeader: cookieHeader,
                                   appID: numericID, externalVersionID: version,
                                   purpose: purpose.rawValue)
        }.value

        guard let raw = json.data(using: .utf8),
              let object = try JSONSerialization.jsonObject(with: raw) as? [String: Any] else {
            throw StoreError.failureType("badBridgeResult", "ent/download result was not JSON")
        }

        let status = object["status"] as? Int ?? 0
        let body = object["body"] as? String ?? ""
        let failure = object["failureType"] as? String ?? ""
        let message = object["customerMessage"] as? String ?? ""

        AppLog.info("ent/download (encoder) HTTP " + String(status)
                    + ", " + String(body.utf8.count) + " bytes"
                    + (failure.isEmpty ? "" : ", failureType " + failure), .download)

        // A 200 with a plist and no failureType is the only success. A gateway
        // error arrives as a short non-plist body that any looser check would
        // accept.
        if failure.isEmpty && status == 200 && !body.isEmpty {
            let plist = (try? PropertyListSerialization.propertyList(
                from: Data(body.utf8), options: [], format: nil)) as? [String: Any]

            if let plist {
                return plist
            }

            throw StoreError.failureType("unparsable",
                                         "ent/download body was not a property list")
        }

        throw StoreError.failureType(failure.isEmpty ? "http" + String(status) : failure,
                                     message.isEmpty ? "ent/download returned " + String(status) : message)
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
        let attempts: [(label: String, token: String, signed: Bool, sendCookie: Bool)] = [
            ("cookie+passwordToken", account.passwordToken, false, true),
            // Second attempt, and the first one that changes a single variable.
            //
            // Every attempt so far answered 2042 "sign in" while the jar held
            // the full nineteen-cookie session Apple had just issued, and
            // ent/download answered 500 with an empty body. Both read as a
            // contradiction rather than a gap: the jar already carries an
            // X-Token set by Apple for this account, and the header above sends
            // a different value under the same name. This attempt sends only the
            // session.
            ("cookie only", "", false, true),
            // Exactly what ipatool sends, and nothing else:
            // appstore_download_product.go sets Content-Type, iCloud-DSID and
            // X-Dsid, and no X-Token, no Cookie, no store-front. Every attempt
            // above has carried cookies this request was never supposed to
            // have, and a session cookie on a request that expects only two
            // DSID headers is a good reason to answer "sign in".
            ("ipatool headers", "", false, false),
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
        mirror("download: pod " + (account.pod.isEmpty ? "none" : account.pod)
               + ", cookies " + String(replayValueCount) + ", "
               + String(replayHeaderLength) + " chars")

        var licenceFailure: (String, String)?
        var lastError: Error = StoreError.failureType("download", "every attempt failed")

        for attempt in attempts {
            var request = URLRequest(url: components.url!)
            request.httpMethod = "POST"
            request.setValue("application/x-apple-plist", forHTTPHeaderField: "Content-Type")
            // upstream's purchase operation uses 2.18 rather than the default.
            request.setValue(Self.storeUserAgent, forHTTPHeaderField: "User-Agent")
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
            if attempt.sendCookie, !capturedCookieHeader.isEmpty {
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

            // The fields, not the bytes -- responseDetail says why the bytes were
            // ever printed and why 4096 of them cost a session.
            AppLog.info("download attempt [" + attempt.label + "] HTTP " + String(status)
                        + ", " + String(responseData.count) + " bytes, "
                        + Self.responseDetail(from: responseData), .download)
            mirror("download attempt [" + attempt.label + "] HTTP " + String(status)
                   + ", " + String(responseData.count) + " bytes, "
                   + Self.responseDetail(from: responseData))

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
            // A 2042 that arrives in metrics rather than as the failure type is
            // the same answer, and dropping it here meant the retry that
            // discards a stale kbsync blob never saw it.
            let reason: String
            if !failure.isEmpty {
                reason = failure
            } else if Self.staleBlobFailureTypes.contains(code) {
                reason = code
            } else {
                reason = "download"
            }
            lastError = StoreError.failureType(reason, message)
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
                AppLog.error("403 body: " + Self.responseDetail(from: data), .network)
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

            // The body travels with the redirect, and for authenticate that body
            // is the Apple ID password. Refusing a Location that leaves Apple's
            // domain is the only way that guarantee does not depend on what the
            // response happens to say.
            guard Self.isAppleHost(next.host) else {
                AppLog.warn("refusing redirect off Apple's domain: "
                            + next.absoluteString + " from "
                            + (signed.url?.absoluteString ?? "?"), .network)

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
