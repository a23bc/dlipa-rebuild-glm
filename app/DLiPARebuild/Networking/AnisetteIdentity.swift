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

        var error: NSError?
        guard let raw = bridge?.headers(encoded, error: &error) else {
            throw NSError(domain: "AnisetteIdentity", code: 1, userInfo: [
                NSLocalizedDescriptionKey: error?.localizedDescription
                    ?? "the bridge returned no anisette response",
            ])
        }

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
