import Foundation

/// How a sign-in request is started and built, kept apart from the client
/// that owns the session state it reads.
///
/// These two decisions used to sit inline in `authenticate`, which pushed the
/// method past the complexity floor the lint job enforces, and moving them out
/// then pushed the file past its length floor. Splitting them into their own
/// file is what the second floor asks for: the client carries the state, and
/// this is one caller's use of it. Nothing here decides anything differently
/// from before -- same conditions, same order of log lines.
///
/// The members touched here are internal rather than private for the same
/// reason the wire log and the response parsing files already do it: the
/// language does not let an extension in another file reach a private one.
extension AppStoreClient {
    /// Which session this call continues, and the address it starts from.
    ///
    /// Three decisions belong together and move as one: whether the jar and the
    /// pod are dropped, what gets logged about the call, and -- when a
    /// verification code is being posted -- how old that code already is. They
    /// lived inline in `authenticate` until that method tripped the complexity
    /// floor the lint job enforces; nothing about what they decide changed on
    /// the way out.
    func beginAuthentication(authCode: String?, code: String,
                                     endpoint: String, attempt: Int) -> String {
        // A sign-in starts from an empty jar. The launch restores the previous
        // account's cookies, and signing in the second account on top of them left
        // that account's X-Token and DSID in the values this call captures -- the
        // new session was minted against the old one and every download through
        // it failed in the guest's request setup.
        //
        // Not a call that continues a challenge, though. Asking for a code and
        // posting it are two calls to `authenticate`, and wiping the jar at the
        // top of the second one deletes the four cookies the first one's answer
        // had just set -- run 511 shows the pair: `itspod=7` minted the
        // challenge, `itspod=17` refused the code, and no `Cookie` was carried
        // between them.
        //
        // The stamp is what makes inheriting safe rather than merely convenient:
        // a code call can only continue a session this process asked for. A code
        // arriving without one -- a restored sheet, a future caller -- would
        // otherwise be posted with the previous account's jar as the launch left
        // it.
        if code.isEmpty || twoFactorAskedAt == nil {
            clearPersistedCookieJar()
            capturedCookieHeader = ""
            capturedCookieValues = [:]
            twoFactorAskedAt = nil
            authenticationPod = nil
        }

        // Where this request goes. The reference client normalizes the bag's URL
        // to a trailing slash because the bare path is refused, and a developer
        // override replaces the whole thing -- see authenticateURL below.
        let url = Self.authenticateURL(endpoint)

        AppLog.info("authenticating against " + url + " attempt " + String(attempt)
                    + (authCode == nil ? " (no 2FA)" : " (with 2FA)"), .auth)

        // How old the code is by the time it leaves. The ladder in front of the
        // application is the reason this can be long: run 511 spent 125 seconds
        // and six code requests -- 403, 204, 204, 204, 404, then a 200 from
        // MZFinance -- starting 13 seconds after the challenge was minted. A
        // rotating code does not survive that, and whether it did here is a
        // number this line answers.
        if let askedAt = twoFactorAskedAt {
            AppLog.info("code posted " + String(Int(Date().timeIntervalSince(askedAt)))
                        + "s after apple asked for it", .auth)
        }

        return authenticationPod ?? url
    }

    /// One authenticate request, built the way the reference client builds it:
    /// the plist body under a urlencoded name, the Configurator user agent, the
    /// session this sign-in already holds, and a log line naming what went on it.
    ///
    /// The signature is not here -- it is computed per dispatch inside
    /// `signedRequest`, over exactly these bytes.
    func authenticationRequest(to address: String, body: Data) throws -> URLRequest {
        var request = URLRequest(url: try Self.trustedEndpoint(address))
        request.httpMethod = "POST"
        // The reference client names this body `application/x-apple-plist`; we
        // have always named it urlencoded, which Apple has answered with HTTP
        // 200 often enough to keep. The difference is one field of the request
        // the edge keeps refusing, so it is a typed field rather than a code
        // change -- and the signature covers the bytes, not this header.
        request.setValue(DevState.contentTypeOverride ?? Self.authenticateContentType,
                         forHTTPHeaderField: "Content-Type")
        request.setValue(Self.authenticateUserAgent, forHTTPHeaderField: "User-Agent")
        request.httpBody = body

        // A 2FA challenge belongs to a session, not to an account. The reference
        // client builds the client that posts authenticate with a cookie jar
        // (upstream pkg/appstore/appstore.go:101), so its code goes back with the
        // `itspod` and `mzf_in` the answer asking for it just set, and Apple
        // routes the verification to the instance that minted the challenge. We
        // captured those cookies and never replayed them, so run 511 posted the
        // code with no `Cookie`, was served by a different pod, and got
        // `MZFinance.BadLogin.Configurator_message` -- the same body Apple uses
        // for a code it did not accept (upstream appstore_login.go:420).
        if !capturedCookieHeader.isEmpty {
            request.setValue(capturedCookieHeader, forHTTPHeaderField: "Cookie")
        }

        // What actually goes out, header by header. Apple routes a sign-in to a
        // regional pod, and a value in here is the only thing that can carry the
        // previous account's region into this one.
        AppLog.info("authenticate request to " + (request.url?.absoluteString ?? "?")
                    + " headers: " + Self.describeRequestHeaders(request), .auth)

        // The names only, read off the request itself. This session turns
        // `httpShouldSetCookies` off on purpose, so `HTTPCookieStorage` stays
        // empty and a line drawn from it reported "none" beside a request that
        // did carry the session -- which is how run 511 read as no cookies at
        // all. The values are session credentials, so they stay out of a log
        // anyone can share; a name answers what the question was asked for.
        let carried = request.value(forHTTPHeaderField: "Cookie")?
            .split(separator: ";")
            .map { $0.trimmingCharacters(in: .whitespaces)
                .split(separator: "=").first.map(String.init) ?? "" } ?? []
        AppLog.info("authenticate carries cookies: "
                    + (carried.isEmpty ? "none" : carried.joined(separator: ",")), .auth)

        return request
    }
}
