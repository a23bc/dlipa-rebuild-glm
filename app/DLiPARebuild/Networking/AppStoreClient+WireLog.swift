import Foundation

/// The clear-text wire log behind the developer-state switch, kept out of
/// `AppStoreClient` so that removing it is deleting this file and one call.
///
/// `docs/probes/developer-state.md` holds the reason it exists, the ruling that
/// permits credentials in the log while the app is a development build, and the
/// list of things that have to go before a release is prepared.
extension AppStoreClient {
    /// Every header, name and value, sorted -- the un-redacted sibling of
    /// `redactedHeaders`, reachable only while the developer-state row is on.
    static func describedHeaders(_ headers: [AnyHashable: Any]) -> String {
        headers.keys.map { key in
            String(describing: key) + "=" + String(describing: headers[key] ?? "")
        }.sorted().joined(separator: ", ")
    }

    /// A body for the log: text where it is text, a hex prefix where it is not,
    /// newlines folded because the window is line-based, and the whole thing
    /// capped so a 46 KB plist cannot push the interesting lines out of view.
    static func bytesForLog(_ input: Data) -> String {
        guard !input.isEmpty else { return "none" }

        let head = Data(input.prefix(4096))

        if let text = String(data: head, encoding: .utf8) {
            return text.replacingOccurrences(of: "\n", with: " ")
                + (input.count > 4096 ? " … (" + String(input.count) + " bytes)" : "")
        }

        return head.prefix(64).map { String(format: "%02x", $0) }.joined()
            + " (" + String(input.count) + " bytes)"
    }

    /// The whole exchange, headers and bodies included, while the developer
    /// state row is on. The status line beside this one says what came back;
    /// this says what was carried.
    ///
    /// It is the pair that ended the run around the 301. With only a status and
    /// a length, three different faults -- an endpoint that does not exist at
    /// that host, an edge that moves it without saying where, and an application
    /// that answers with nothing -- print the same thing. With the headers, the
    /// second was measured rather than argued about: `HTTP 301`, `Content-Type:
    /// text/html`, and no `Location` at all.
    ///
    /// Clear text on purpose: this is a development build, and the state on the
    /// wire is the thing under investigation.
    static func logWireExchange(_ request: URLRequest, body: Data,
                                reply: HTTPURLResponse, replyBody: Data) {
        guard DevState.enabled else { return }

        let sent: [AnyHashable: Any] = request.allHTTPHeaderFields ?? [:]

        AppLog.info("wire out " + (request.httpMethod ?? "?")
                    + " " + (request.url?.absoluteString ?? "?")
                    + " | " + Self.describedHeaders(sent)
                    + " | body " + Self.bytesForLog(body), .network)
        AppLog.info("wire in " + String(reply.statusCode)
                    + " " + (reply.url?.absoluteString ?? "?")
                    + " | " + Self.describedHeaders(reply.allHeaderFields)
                    + " | body " + Self.bytesForLog(replyBody), .network)
    }
}
