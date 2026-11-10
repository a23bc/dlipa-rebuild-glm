import Foundation

/// How one authentication answer is classified and then phrased.
///
/// Split out of `AppStoreClient` for two reasons. The file had reached 2,498
/// lines against a `file_length` error at 2,500, and this cluster is the part
/// that is genuinely separable: nothing here touches the session, the signer,
/// or the account -- it reads a response and says what it means. The other
/// reason is the one that matters to a reader: three of these six members exist
/// because of a measured instability rather than a documented rule, and putting
/// the measurements beside each other makes that visible instead of scattering
/// it through 2,400 lines.
extension AppStoreClient {
    /// How many times a single authentication request is sent. Three is what
    /// ipatool does, with the delays below between the tries; a probe can ask
    /// for more, and the number it is asking for is the one this file cannot
    /// produce from a machine: how many tries a real account needs before a
    /// Store pod answers as an application rather than as front-end noise.
    static var authenticationRequestAttempts: Int {
        DevState.authAttemptsOverride ?? 3
    }

    /// 10s, then 20s, then 30s -- the doubling the reference client does,
    /// capped at the 30s it caps at. The list is indexed with a clamp, so a
    /// probe asking for twelve tries waits thirty seconds between the later
    /// ones instead of running off the end.
    static let authenticationRetryDelays: [UInt64] = [10, 20, 30]

    /// Statuses a Store pod returns when it is not ready to answer. Treating
    /// these as final is what surfaced a 404 to the user on the 2FA attempt.
    static func isTransientAuthenticationStatus(_ statusCode: Int) -> Bool {
        switch statusCode {
        case 204, 403, 404, 429:
            return true
        default:
            return statusCode / 100 == 5
        }
    }

    /// Whether this answer says the endpoint is not there, rather than the
    /// credentials not being accepted.
    ///
    /// A 3xx joins the transient set only when it carries no `Location`. On
    /// 2026-11-10 an identical unsigned POST to that path, retried three times
    /// from the same machine seconds apart, came back 404, then 204, then a 301
    /// with no `Location` at all -- the same unstable answer arriving in three
    /// different shapes. Treating the third one as final turned a bad second
    /// into a failed sign-in, and there is nothing to follow when the redirect
    /// names no destination.
    ///
    /// Credentials never look like this. Those are refused with HTTP 200 and a
    /// `failureType`, which is how 2034, 2002, 2083 and 9610 have always
    /// arrived, and a bad signature is a 401 or 403 with a body to read.
    static func isTransientAuthentication(_ http: HTTPURLResponse) -> Bool {
        if isTransientAuthenticationStatus(http.statusCode) {
            return true
        }

        guard (300..<400).contains(http.statusCode) else { return false }

        return (http.value(forHTTPHeaderField: "Location") ?? "").isEmpty
    }

    /// A two-hundred status with nothing to parse is not an answer to sign in
    /// with, and it has to be said before anything tries to read the body.
    ///
    /// 204 is inside the transient set, so reaching this at all means the backoff
    /// retries were spent. validate() then accepts it, because 204 is a
    /// two-hundred, and the plist parse of the empty body failed with the
    /// system's own complaint -- "the data couldn't be read because it isn't in
    /// the correct format" -- which is what a person saw for a sign-in that never
    /// reached an account handler.
    ///
    /// It lives here rather than inline because this call site cannot afford the
    /// two branches an `if` with an `||` costs: the function stood at complexity
    /// 19 on main, my inline version reached 21, and `Lint Swift` turned red --
    /// the rule's error threshold sits somewhere between the two, and a baseline
    /// that close to it is not something to spend on the shape of a response. A
    /// successful authenticate always carries tokens, so an empty body with a 200
    /// belongs to the same sentence.
    static func rejectEmptyAnswer(http: HTTPURLResponse, data: Data) throws {
        guard http.statusCode == 204 || data.isEmpty else { return }

        AppLog.error("authenticate ended with HTTP " + String(http.statusCode)
                     + " and " + String(data.count) + " bytes after "
                     + String(authenticationRequestAttempts)
                     + " request tries, none of which produced a body", .auth)

        throw StoreError.failureType("no-content",
                                     "the store answered with no content (HTTP 204); sign in again")
    }

    /// What a non-2xx body is worth telling the person, in one sentence.
    ///
    /// The body used to be pasted in as far as 200 characters went, which is
    /// right when Apple sends a plist -- the `failureType` and `customerMessage`
    /// inside it are the answer. It is wrong when Apple sends an edge page: an
    /// HTML "301 Moved Permanently" from `Server: Apple` adds nothing the status
    /// code does not already say, and it buried the one fact worth knowing --
    /// that the request never reached the application, so the credentials are
    /// not what is being refused.
    static func explainRejection(http: HTTPURLResponse, data: Data) -> String {
        let type = http.value(forHTTPHeaderField: "Content-Type") ?? ""
        let body = String(data: data, encoding: .utf8) ?? ""

        guard type.contains("html") else { return String(body.prefix(200)) }

        let size = data.isEmpty ? "no body" : String(data.count) + " bytes"

        return "the request was answered by Apple's front end, not by the store "
            + "(HTTP " + String(http.statusCode) + ", " + type + ", " + size
            + "). This is not your password: a credential problem arrives as "
            + "HTTP 200 with a failureType."
    }
}
