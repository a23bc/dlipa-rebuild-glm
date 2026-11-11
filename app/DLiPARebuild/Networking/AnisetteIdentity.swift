import Foundation

/// The machine identity the store's authenticate request is built to receive.
///
/// The Go bridge provisions it (gsa) and proves it (adid/fairplayd) and owns no
/// storage, so the opaque state lives in the keychain here. One identity per
/// device: a new one on every sign-in reads to Apple as a new machine, and the
/// store answers a new machine differently from the one it has seen.
enum AnisetteIdentity {
    private static let bridge = SapbridgeNewAnisette()
    private static let lock = NSLock()

    /// Fetches one fresh set of headers. The state is advanced and saved.
    static func headers() throws -> [String: String] {
        lock.lock()
        defer { lock.unlock() }

        let previous = Keychain.anisetteState()
        let encoded = previous?.base64EncodedString() ?? ""

        guard let bridge else {
            throw NSError(domain: "AnisetteIdentity", code: 1, userInfo: [
                NSLocalizedDescriptionKey: "the anisette bridge is unavailable",
            ])
        }

        // Nullable return plus NSError** imports as a throwing, non-optional
        // call: the nil case is folded into the error.
        let raw = try bridge.headers(encoded)

        guard let data = raw.data(using: .utf8),
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let headers = object["headers"] as? [String: String] else {
            throw NSError(domain: "AnisetteIdentity", code: 2, userInfo: [
                NSLocalizedDescriptionKey: "could not read the anisette response",
            ])
        }

        var nextBytes = 0

        if let next = object["state"] as? String, let fresh = Data(base64Encoded: next) {
            nextBytes = fresh.count
            Keychain.saveAnisetteState(fresh)
        }

        AppLog.info("anisette identity: " + String(headers.count) + " headers, state "
                    + String(previous?.count ?? 0) + " -> " + String(nextBytes) + " bytes", .sap)
        AppLog.info("anisette headers: " + headers.keys.sorted().joined(separator: ", "), .sap)

        return headers
    }
}
