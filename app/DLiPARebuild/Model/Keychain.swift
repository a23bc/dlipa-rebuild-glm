import Foundation
import Security

/// Removing a password this app used to write.
///
/// Nothing here stores a credential any more. The password was written at every
/// sign-in for a token refresh that was never implemented -- the only reader was
/// a private method nothing called -- which left a long-lived Apple ID password
/// in the keychain with no feature behind it. Accounts deleted by an older
/// build still have one, so delete(for:) stays until those are gone.
enum Keychain {
    private static let service = "com.a23bc.dliparebuild.password"

    private static func query(_ email: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: email,
        ]
    }

    static func delete(for email: String) {
        guard !email.isEmpty else { return }
        SecItemDelete(query(email) as CFDictionary)
    }
}
