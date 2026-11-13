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

    /// Finishes the Store provisioning step and returns the Store AMD proof.
    /// The state passed in is the one the SP answer was produced against; the
    /// returned state replaces it.
    static func provisionStore(state: Data,
                               challenge: String,
                               kbsync: Data,
                               identity: [String: String],
                               guid: String) throws -> Data {
        guard let bridge else {
            throw NSError(domain: "AnisetteIdentity", code: 3, userInfo: [
                NSLocalizedDescriptionKey: "the anisette bridge is unavailable",
            ])
        }

        let identityData = try JSONSerialization.data(withJSONObject: identity, options: [])
        let identityJSON = String(data: identityData, encoding: .utf8) ?? "{}"

        let raw = try bridge.provisionStore(state.base64EncodedString(),
                                            challenge: challenge,
                                            kbsync: kbsync.base64EncodedString(),
                                            identityJSON: identityJSON,
                                            hardwareHex: guid)

        guard let data = raw.data(using: .utf8),
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let next = object["state"] as? String,
              let fresh = Data(base64Encoded: next) else {
            throw NSError(domain: "AnisetteIdentity", code: 4, userInfo: [
                NSLocalizedDescriptionKey: "could not read the provisioning response",
            ])
        }

        Keychain.saveAnisetteState(fresh)

        AppLog.info("store provisioning produced a " + String(fresh.count) + "-byte state", .sap)

        return fresh
    }

    /// Mints the Store proof for one endpoint from the provisioned state, the
    /// way the reference does before a download: no provisioning exchange.
    static func storeProof(endpoint: String, guid: String) throws -> [String: String] {
        guard let bridge else {
            throw NSError(domain: "AnisetteIdentity", code: 7, userInfo: [
                NSLocalizedDescriptionKey: "the anisette bridge is unavailable",
            ])
        }

        let state = Keychain.anisetteState() ?? Data()
        let raw = try bridge.storeProof(state.base64EncodedString(),
                                        endpoint: endpoint,
                                        hardwareHex: guid)

        guard let data = raw.data(using: .utf8),
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let headers = object["headers"] as? [String: String] else {
            throw NSError(domain: "AnisetteIdentity", code: 8, userInfo: [
                NSLocalizedDescriptionKey: "could not read the store proof response",
            ])
        }

        if let next = object["state"] as? String, let fresh = Data(base64Encoded: next) {
            Keychain.saveAnisetteState(fresh)
        }

        return headers
    }

    /// Runs the provisioning a download endpoint's AMD-Action asks for and
    /// returns the proof for that endpoint.
    static func downloadProof(challenge: String,
                              endpoint: String,
                              identity: [String: String],
                              guid: String) throws -> [String: String] {
        guard let bridge else {
            throw NSError(domain: "AnisetteIdentity", code: 5, userInfo: [
                NSLocalizedDescriptionKey: "the anisette bridge is unavailable",
            ])
        }

        let state = Keychain.anisetteState() ?? Data()
        let identityData = try JSONSerialization.data(withJSONObject: identity, options: [])
        let identityJSON = String(data: identityData, encoding: .utf8) ?? "{}"

        let raw = try bridge.downloadProof(state.base64EncodedString(),
                                           challenge: challenge,
                                           endpoint: endpoint,
                                           identityJSON: identityJSON,
                                           hardwareHex: guid)

        guard let data = raw.data(using: .utf8),
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let headers = object["headers"] as? [String: String] else {
            throw NSError(domain: "AnisetteIdentity", code: 6, userInfo: [
                NSLocalizedDescriptionKey: "could not read the download proof response",
            ])
        }

        if let next = object["state"] as? String, let fresh = Data(base64Encoded: next) {
            Keychain.saveAnisetteState(fresh)
        }

        AppLog.info("download proof produced " + String(headers.count) + " headers", .sap)

        return headers
    }
}
