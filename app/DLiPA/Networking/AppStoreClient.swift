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

    /// The UA the original DLiPA shipped. Apple gates the private bag on the
    /// Configurator UA: with a generic UA the response contains none of the
    /// sign-sap-* keys at all.
    static let bagUserAgent =
        "Configurator/2.17 (Macintosh; OS X 15.2; 24C5089c) AppleWebKit/0620.1.16.11.6"

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

    // MARK: - Bag

    func fetchBag(guid: String) async throws -> StoreBag {
        var components = URLComponents(string: "https://init.itunes.apple.com/bag.xml")!
        components.queryItems = [URLQueryItem(name: "guid", value: guid)]
        var request = URLRequest(url: components.url!)
        request.httpMethod = "GET"
        request.setValue("application/xml", forHTTPHeaderField: "Accept")
        request.setValue(Self.bagUserAgent, forHTTPHeaderField: "User-Agent")

        let (data, response) = try await session.data(for: request)
        try validate(response, data: data)
        let bag = try StoreBag.parse(xml: data)

        // The bag is the only place the SAP endpoints come from. If it came back
        // without them, every later step fails with a message that will not say
        // why, so record it here.
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

    /// Signs in. `authCode` is appended to the password for 2FA, exactly as the
    /// original DLiPA did.
    func authenticate(email: String,
                      password: String,
                      authCode: String,
                      guid: String,
                      endpoint: String,
                      signer: SAPSigner) async throws -> Account {
        // A missing trailing slash gets a 204 and nothing else happens.
        let url = endpoint.hasSuffix("/") ? endpoint : endpoint + "/"
        AppLog.info("authenticating against " + url, .auth)

        var request = URLRequest(url: URL(string: url)!)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.setValue(Self.bagUserAgent, forHTTPHeaderField: "User-Agent")

        let payload: [String: Any] = [
            "appleId": email,
            "attempt": "1",
            "guid": guid,
            "password": password + authCode.replacingOccurrences(of: " ", with: ""),
            "rmp": "0",
            "why": "signIn",
        ]
        // The header says urlencoded but the body really is a plist; this is
        // what Apple accepts and what the signature must cover.
        request.httpBody = try PropertyListSerialization.data(
            fromPropertyList: payload, format: .xml, options: 0)

        let (data, response) = try await signedRequest(
            request, signer: signer, redirects: 4)
        try validate(response, data: data)

        let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil)
            as? [String: Any] ?? [:]

        // Apple reports recoverable failures in the body with HTTP 200.
        if let failure = plist["failureType"] as? String, !failure.isEmpty {
            let message = plist["customerMessage"] as? String ?? ""
            throw StoreError.failureType(failure, message)
        }

        let accountInfo = plist["accountInfo"] as? [String: Any] ?? [:]
        let address = accountInfo["address"] as? [String: Any] ?? [:]

        return Account(
            email: accountInfo["appleId"] as? String ?? email,
            passwordToken: plist["passwordToken"] as? String ?? "",
            dsid: plist["dsPersonId"] as? String ?? "",
            storefront: headerValue(response, "X-Set-Apple-Store-Front") ?? "",
            pod: headerValue(response, "pod") ?? "",
            firstName: address["firstName"] as? String ?? "",
            lastName: address["lastName"] as? String ?? "")
    }

    // MARK: - Download

    /// Requests a download from `ent/download`, which is where Apple now serves
    /// the bag's `volumeStoreDownloadProduct` key.
    func requestDownload(appId: String,
                         externalVersionId: String?,
                         guid: String,
                         account: Account,
                         bag: StoreBag,
                         signer: SAPSigner) async throws -> URL {
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

        var payload: [String: Any] = [
            "creditDisplay": "",
            "guid": guid,
            "kbsync": try signer.kbsync(dsid: account.dsid),
            "salableAdamId": appId,
            "serialNumber": try signer.serialNumber(),
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

        // A failure on the download leg is often a stale kbsync blob. Drop it
        // so the next attempt regenerates rather than replaying the rejected
        // value; ipatool does the same, but only once, and never for a fresh
        // blob.
        if let failure = plist["failureType"] as? String, !failure.isEmpty {
            let message = plist["customerMessage"] as? String ?? ""
            if failure == "2034" || failure == "2042" || failure == "1008" {
                signer.invalidateKBSync(dsid: account.dsid)
            }
            throw StoreError.failureType(failure, message)
        }

        guard let items = plist["songList"] as? [Any],
              let first = items.first as? [String: Any],
              let urlString = first["URL"] as? String,
              let url = URL(string: urlString) else {
            throw StoreError.failureType("Invalid response", "")
        }
        return url
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
            AppLog.debug("signed request to " + (signed.url?.absoluteString ?? "?")
                         + " returned " + String(http.statusCode), .network)
            if http.statusCode == 403 {
                let hadSignature = signed.value(forHTTPHeaderField: "X-Apple-ActionSignature") != nil
                AppLog.error("403 from " + (signed.url?.host ?? "?")
                             + ", signature attached: " + String(hadSignature), .network)
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
