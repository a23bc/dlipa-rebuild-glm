import Foundation
import Security

/// The account password, kept only so the store token can be refreshed.
///
/// The token Apple hands back at sign-in is short lived; the password is not.
/// Without this, every launch reuses a token from a previous session and the
/// store answers "sign in required" (2042), which is exactly what version
/// history and downloads were hitting.
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
        guard !password.isEmpty, !email.isEmpty else { return }
        var item = query(email)
        SecItemDelete(item as CFDictionary)
        item[kSecValueData as String] = Data(password.utf8)
        // AfterFirstUnlock: a refresh may happen while the device is locked if
        // a download was queued, and it must not block on the keychain.
        item[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock
        let status = SecItemAdd(item as CFDictionary, nil)
        if status != errSecSuccess {
            AppLog.warn("keychain save failed with " + String(status), .auth)
        }
    }

    static func password(for email: String) -> String? {
        guard !email.isEmpty else { return nil }
        var item = query(email)
        item[kSecReturnData as String] = true
        item[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        guard SecItemCopyMatching(item as CFDictionary, &out) == errSecSuccess,
              let data = out as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    static func delete(for email: String) {
        guard !email.isEmpty else { return }
        SecItemDelete(query(email) as CFDictionary)
    }
}
