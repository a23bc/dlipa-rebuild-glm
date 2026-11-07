import Foundation
import Security

/// A probe of the two keychain shapes, kept off the mainline until it has been
/// read on device.
///
/// The plan is to move the account tokens, the cookie jar, the device identity
/// and the kbsync blob out of `UserDefaults` and `Library/Caches` and into the
/// keychain. One half of that has never been tested here: the password item uses
/// the classic generic-password query, and it works -- device captures carry
/// `password kept for a session refresh`. The shape the plan calls for is the
/// data-protection keychain with `ThisDeviceOnly`, and the difference matters for
/// exactly the reason the move is being made: a `ThisDeviceOnly` item does not
/// ride along in a backup, while the preferences file it would replace does.
///
/// Nothing about that has ever been exercised by a build signed the way this app
/// is signed -- sideloaded, ad-hoc identity, no keychain-access-groups
/// entitlement of its own. Whether `SecItemAdd` answers 0 under those conditions,
/// and whether an item written in one launch is still there in the next, are
/// questions with answers this repository does not have. Guessing them wrong
/// costs a migration that bricks sign-in on the way back, so they get measured
/// first, in one launch, with no state depending on the result.
enum KeychainProbe {
    private static let service = "com.a23bc.dliparebuild.keychainProbe"
    private static let markerAccount = "marker"

    /// What the probe writes, so a value read back on a later launch is
    /// recognisable as ours and as belonging to a shape that survived.
    private static let markerValue = "probe-" + String(Date().timeIntervalSince1970)

    static func run() {
        probe(label: "classic", dataProtection: false, accessible: kSecAttrAccessibleAfterFirstUnlock)
        probe(label: "data-protection", dataProtection: true,
              accessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)
    }

    /// Write one item and read it back, logging the OSStatus of each step and the
    /// value an earlier launch left behind.
    ///
    /// The item is deliberately not deleted at the end: the question "does a
    /// `ThisDeviceOnly` item survive a relaunch, and does it survive a reinstall"
    /// can only be answered by the next launch seeing what this one wrote. Each
    /// write starts by deleting, so a launch that died mid-probe leaves no
    /// duplicate, and the status of that delete is logged too -- it is the delete
    /// half of the contract either way.
    ///
    /// So `previous` is the previous launch's timestamp, and a launch after an
    /// uninstall that still shows one is the answer to the question the whole
    /// migration rests on: whether the blob can be counted on to outlive the
    /// container it currently sits in.
    private static func probe(label: String, dataProtection: Bool, accessible: CFString) {
        let previous = read(label: label, dataProtection: dataProtection)

        let statuses = write(label: label, dataProtection: dataProtection,
                             accessible: accessible, value: markerValue)
        let readBack = read(label: label, dataProtection: dataProtection)

        // Assembled a field at a time. One expression joining five pieces with
        // two ternaries inside it is something the compiler will not type-check
        // in reasonable time -- the archive said so on the first build of this
        // file -- and a probe that only compiles in a build log is no use here.
        var line = "keychain probe " + label
        line += ": previous=" + (previous ?? "absent")
        line += ", delete=" + String(statuses.delete)
        line += ", add=" + String(statuses.add)
        line += ", read-back=" + (readBack ?? "absent")

        if readBack != markerValue {
            line += " (DIFFERS FROM WHAT WAS WRITTEN)"
        }

        AppLog.info(line, .app)
    }

    private static func query(label: String, dataProtection: Bool) -> [String: Any] {
        var base: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service + "." + label,
            kSecAttrAccount as String: markerAccount,
        ]

        if dataProtection {
            base[kSecUseDataProtectionKeychain as String] = kCFBooleanTrue
        }

        return base
    }

    private static func write(label: String, dataProtection: Bool, accessible: CFString,
                              value: String) -> (delete: OSStatus, add: OSStatus) {
        var attributes = query(label: label, dataProtection: dataProtection)

        let cleared = SecItemDelete(attributes as CFDictionary)

        attributes[kSecValueData as String] = Data(value.utf8)
        attributes[kSecAttrAccessible as String] = accessible

        return (cleared, SecItemAdd(attributes as CFDictionary, nil))
    }

    private static func read(label: String, dataProtection: Bool) -> String? {
        var request = query(label: label, dataProtection: dataProtection)

        request[kSecReturnData as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne

        var item: CFTypeRef?

        guard SecItemCopyMatching(request as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data, let value = String(data: data, encoding: .utf8) else {
            return nil
        }

        return value
    }
}
