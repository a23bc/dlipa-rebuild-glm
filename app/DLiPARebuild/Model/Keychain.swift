import Foundation
import Security

/// The Apple ID password, kept so the store session can be renewed.
///
/// Upstream does this and depends on it: when Apple retires a session token it
/// answers 2034, and ipatool's download command responds by signing in again
/// with the account's own stored password before retrying (cmd/download.go:55).
/// Without the password a 2034 is terminal -- the app can only ask the person to
/// type it again, which is what this avoided until 2026-11-06.
///
/// The password is only ever read by that refresh. It is written after a
/// successful sign-in and deleted with the account.
enum Keychain {
    private static let service = "com.a23bc.dliparebuild.password"

    private static func query(_ email: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: email,
        ]
    }

    static func save(_ password: String, for email: String) {
        guard !email.isEmpty, let data = password.data(using: .utf8) else { return }

        // One credential per account: an overwrite, never a second item.
        SecItemDelete(query(email) as CFDictionary)

        var attributes = query(email)
        attributes[kSecValueData as String] = data
        // Readable after the first unlock, which is when a download can run and
        // not before. Nothing here needs it while the device is locked.
        attributes[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock

        let status = SecItemAdd(attributes as CFDictionary, nil)

        // One line, no value: whether a 2034 can be recovered from is otherwise
        // only knowable by waiting for a 2034.
        if status == errSecSuccess {
            AppLog.info("password kept for a session refresh", .auth)
        } else {
            AppLog.warn("could not keep the password for a session refresh: "
                        + String(status), .auth)
        }
    }

    static func password(for email: String) -> String? {
        guard !email.isEmpty else { return nil }

        var request = query(email)
        request[kSecReturnData as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne

        var item: CFTypeRef?

        guard SecItemCopyMatching(request as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data else {
            return nil
        }

        return String(data: data, encoding: .utf8)
    }

    static func delete(for email: String) {
        guard !email.isEmpty else { return }
        SecItemDelete(query(email) as CFDictionary)
    }

    // MARK: - Anisette state

    /// The opaque machine identity behind the anisette headers. One per device,
    /// not per account: re-provisioning on every sign-in makes the store treat
    /// the phone as a new machine.
    private static let anisetteService = "com.a23bc.dliparebuild.anisette"

    private static func anisetteQuery() -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: anisetteService,
            kSecAttrAccount as String: "state",
        ]
    }

    static func saveAnisetteState(_ data: Data) {
        guard !data.isEmpty else { return }

        SecItemDelete(anisetteQuery() as CFDictionary)

        var attributes = anisetteQuery()
        attributes[kSecValueData as String] = data
        attributes[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock

        let status = SecItemAdd(attributes as CFDictionary, nil)

        if status == errSecSuccess {
            AppLog.info("anisette state kept, " + String(data.count) + " bytes", .sap)
        } else {
            AppLog.warn("could not keep the anisette state: " + String(status), .sap)
        }
    }

    static func anisetteState() -> Data? {
        var request = anisetteQuery()
        request[kSecReturnData as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne

        var item: CFTypeRef?

        guard SecItemCopyMatching(request as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data else {
            return nil
        }

        return data
    }
}
