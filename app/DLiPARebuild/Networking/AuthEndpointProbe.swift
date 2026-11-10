import Foundation

/// Unsigned requests that answer one question without touching an account:
/// is the authentication endpoint answering at all, right now, from here?
///
/// The question got worth asking because the payload was verified complete
/// against the reference client, the hardware identity was restored to the
/// value from the last successful sign-in, and the answer was still an empty
/// 204, an HTML 404, or an HTML 301 with no `Location` -- none of which is how
/// Apple refuses credentials (that is HTTP 200 with a `failureType`). What was
/// left to know was server-side, and a sign-in cannot answer it without the
/// person's password.
///
/// So this sends a body of the right shape with nothing in it: a probe address,
/// a probe password, a zero guid, and no signature at all. The comparison is
/// with two paths that are known to work -- a sibling selector of the same web
/// application, and the download endpoint -- because the useful fact is not
/// "authenticate returns 404" but "authenticate returns 404 while the rest of
/// MZFinance returns 200 from the same host in the same second".
///
/// Repeating the authenticate request three times is the other half: identical
/// requests measured on 2026-11-10 returned 404, then 204, then 301, which is
/// what makes this look like a routing condition rather than a rejection.
enum AuthEndpointProbe {
    private static let probeBody: [String: String] = [
        "appleId": "probe@invalid.local",
        "attempt": "1",
        "guid": "000000000000",
        "password": "not-a-real-password",
        "rmp": "0",
        "why": "signIn",
    ]

    static func run() async {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpShouldSetCookies = false
        configuration.timeoutIntervalForRequest = 15

        // Redirects are refused on purpose: the destination, or its absence, is
        // the measurement. Following them would report the answer at the far
        // end and lose the fact that this hop said nothing.
        let session = URLSession(configuration: configuration,
                                 delegate: NoAutoRedirectDelegate(),
                                 delegateQueue: nil)
        defer { session.invalidateAndCancel() }

        let body = try? PropertyListSerialization.data(fromPropertyList: probeBody,
                                                       format: .xml,
                                                       options: 0)

        for tryNumber in 1...3 {
            await report(session, named: "authenticate try " + String(tryNumber),
                         path: "/WebObjects/MZFinance.woa/wa/authenticate/",
                         on: "buy.itunes.apple.com",
                         body: body ?? Data())
        }

        await report(session, named: "sibling selector (logout)",
                     path: "/WebObjects/MZFinance.woa/wa/logout",
                     on: "buy.itunes.apple.com",
                     body: body ?? Data())

        await report(session, named: "download dispatch",
                     path: "/WebObjects/DownloadDispatch.woa/wa/ent/download",
                     on: "downloaddispatch.itunes.apple.com",
                     body: body ?? Data())
    }

    /// One request, one line: status, content type, whether a `Location` came,
    /// and how many bytes arrived with them.
    private static func report(_ session: URLSession, named: String, path: String,
                               on host: String, body: Data) async {
        var request = URLRequest(url: URL(string: "https://" + host + path)!)
        request.httpMethod = "POST"
        request.httpBody = body
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.setValue(AppStoreClient.bagUserAgent, forHTTPHeaderField: "User-Agent")

        do {
            let (data, response) = try await session.data(for: request)
            let http = response as? HTTPURLResponse

            AppLog.info("endpoint probe " + named + " -> " + describe(http, data: data), .network)
        } catch {
            AppLog.error("endpoint probe " + named + " failed: "
                         + error.localizedDescription, .network)
        }
    }

    private static func describe(_ http: HTTPURLResponse?, data: Data) -> String {
        guard let http else { return "not an HTTP response" }

        let type = http.value(forHTTPHeaderField: "Content-Type") ?? "no content-type"

        var destination = "no Location"

        if let location = http.value(forHTTPHeaderField: "Location"), !location.isEmpty {
            destination = "Location " + location
        }

        let head = String(decoding: data.prefix(24), as: UTF8.self).replacingOccurrences(of: "\n", with: " ")
        let bodyKind = data.isEmpty ? "empty body" : String(data.count) + " bytes: " + head

        return "HTTP " + String(http.statusCode) + ", " + type + ", " + destination + ", " + bodyKind
    }
}
