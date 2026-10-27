import CryptoKit
import Foundation
import UIKit

/// The device identity used for SAP signing and kbsync generation.
///
/// Must be exactly 6 bytes: ent/download rejects any other length, and the
/// original DLiPA used a random UUID which cannot work there.
struct HardwareIdentity {
    /// Raw bytes. Must be 6 for ent/download.
    let bytes: Data

    /// Uppercase hex, e.g. A4B2C3D4E5F6. Used as the guid query parameter
    /// and the plist guid field.
    var guid: String {
        // Uppercase hex of the raw bytes, e.g. A4B2C3D4E5F6. This was a Go
        // helper; the conversion is small enough to live here, which keeps the
        // signing path free of the Go bridge.
        bytes.map { String(format: "%02X", $0) }.joined()
    }

    /// Where the persisted identity lives.
    static let storageKey = "com.a23bc.dliparebuild.hardwareIdentity"

    /// Posted after `regenerate()`. Anything holding a live SAP session has to
    /// drop it: the guest was opened with the old hardware id, and the signing
    /// requests it produces would name a machine that no longer exists.
    static let didChangeNotification =
        Notification.Name("com.a23bc.dliparebuild.hardwareIdentityDidChange")

    /// A fixed 6-byte identity, generated once and then persisted.
    ///
    /// ipatool derives the guid from the machine's MAC address
    /// (machineIdentity in pkg/appstore/machine_id.go: uppercase hex of the
    /// hardware address), so it is a machine constant there, not a per-session
    /// value. iOS exposes no MAC, so the same constant has to be supplied some
    /// other way, and identifierForVendor alone is not enough: it is stable
    /// only while some app from the vendor is installed, and it changes if they
    /// are all removed. A changed guid reads to Apple as a different machine
    /// and silently invalidates every cached kbsync blob, so the first value is
    /// written to defaults and reused from then on.
    ///
    /// It must also equal the hardware id handed to the SAP guest: the
    /// emulator's request builder compares the two and fails with
    /// "authentication hardware identity mismatch" when they differ.
    static func current() -> HardwareIdentity {
        let defaults = UserDefaults.standard

        if let saved = defaults.data(forKey: storageKey), saved.count == 6 {
            return HardwareIdentity(bytes: saved)
        }

        let seed = UIDevice.current.identifierForVendor?.uuidString ?? "dlipa-fallback"
        let digest = Array(SHA256.hash(data: Data(seed.utf8)))
        let bytes = Data(digest.prefix(6))
        defaults.set(bytes, forKey: storageKey)
        AppLog.info("hardware identity generated once: "
                    + bytes.map { String(format: "%02X", $0) }.joined(), .sap)
        return HardwareIdentity(bytes: bytes)
    }

    /// Replaces the stored identity with a new random one.
    ///
    /// The seed is a fresh UUID rather than the vendor identifier, so every call
    /// produces a different value. Apple treats the guid as the machine, so this
    /// is only for when the current one is unusable -- a session bound to a
    /// stale identity, or a decision to start over as a new device. It signs the
    /// user out and drops every kbsync blob tied to the old identity.
    @discardableResult
    static func regenerate() -> HardwareIdentity {
        let seed = UUID().uuidString
        let digest = Array(SHA256.hash(data: Data(seed.utf8)))
        let bytes = Data(digest.prefix(6))
        UserDefaults.standard.set(bytes, forKey: storageKey)
        AppLog.info("hardware identity regenerated: "
                    + bytes.map { String(format: "%02X", $0) }.joined(), .sap)
        NotificationCenter.default.post(name: didChangeNotification, object: nil)
        return HardwareIdentity(bytes: bytes)
    }
}

/// Owns the SAP session. Create once after login and share for the whole
/// session; the session is stateful, so re-signing is required after any
/// redirect.
final class SAPSigner {
    /// The Go bridge's live SAP session.
    ///
    /// This used to be an opaque handle into sap_guest.c, a C engine running an
    /// OS X 10.9 x86-64 guest. That route can sign, but it cannot produce a
    /// kbsync blob, and without kbsync there is no download and no version
    /// history. The Go bridge runs the macOS 27 arm64 machine package instead --
    /// the same code upstream ipatool uses -- and it covers signing and kbsync
    /// with one session.
    private let bridge: SapbridgeSigner
    let hardware: HardwareIdentity

    init(setupURL: String, certURL: String, version: Int32, hardware: HardwareIdentity) throws {
        // The Go bridge fetches the setup certificate, runs both exchange legs
        // and keeps the machine alive for the whole session. The app only has to
        // say which SAP endpoints the bag named and which device identity to
        // present.
        self.hardware = hardware

        var error: NSError?
        guard let signer = SapbridgeNew(setupURL, certURL, version,
                                        hardware.bytes, &error) else {
            let detail = error?.localizedDescription ?? "unknown"
            AppLog.error("SAP handshake FAILED: " + detail, .sap)
            fputs("[DLiPA] SAP handshake FAILED: " + detail + "\n", stderr)
            throw NSError(domain: "SAPSigner", code: 2, userInfo: [
                NSLocalizedDescriptionKey: detail,
            ])
        }
        self.bridge = signer
        AppLog.info("SAP signer ready via the arm64 bridge, hardware " + hardware.guid, .sap)
    }

    /// The value for the X-Apple-ActionSignature header.
    func signatureHeaderValue(for body: Data) throws -> String {
        AppLog.info("sign: entering with " + String(body.count) + " bytes", .sap)
        var error: NSError?
        // The generated header declares this as non-optional NSString, so a
        // failure shows up only as a non-nil error. Checking the error first
        // keeps the reason visible; the string itself is never nil.
        let value = bridge.signatureHeaderValue(body, error: &error)
        if let error {
            AppLog.error("sign FAILED: " + error.localizedDescription, .sap)
            throw NSError(domain: "SAPSigner", code: 4, userInfo: [
                NSLocalizedDescriptionKey: error.localizedDescription,
            ])
        }
        AppLog.info("sign: returned header=" + String(value.count), .sap)
        return value
    }

    /// The FairPlay kbsync blob required by ent/download.
    ///
    /// Generating a blob runs the emulated Apple binaries, which is expensive,
    /// and the blob is stable for a given account and device. So it is cached
    /// and reused. A blob Apple rejected is discarded so the next call
    /// regenerates it; a fresh blob is never retried.
    /// E1-a: opens the Store runtime on the machine this signer already runs on,
/// and reports how long it took. The runtime shares the guest rather than
/// creating one, because a second emulator cannot be allocated here.
func storeSmoke(dsid: String, token: String, storefront: String) throws -> String {
    try bridge.storeSmoke(dsid, token: token, storefront: storefront)
}

func kbsync(dsid: String) throws -> Data {
        let key = Self.cacheKey(dsid: dsid, guid: hardware.guid)
        if let cached = Self.kbsyncCache.object(forKey: key) {
            return cached as Data
        }
        // Generated on the session's own machine, not a fresh one. Two
        // emulators do not fit: each is ~173 MB resident, and the second
        // uc_open dies inside QEMU with exit(1), which iOS records as a silent
        // kill with no crash report.
        // Swift imports this one as throwing, the same way it does close(): a
        // nullable return plus an NSError out-parameter becomes one call that
        // throws. signatureHeaderValue keeps its explicit error pointer because
        // its return is non-nullable, which is why the two look different here.
        let fresh: Data
        do {
            // Swift imports this as a throwing call returning Data, not Data?:
            // the nullable return is folded into the throw, so an empty blob is
            // the only thing left to check here.
            let blob = try bridge.generateKBSync(dsid)
            guard !blob.isEmpty else {
                throw NSError(domain: "SAPSigner", code: 3, userInfo: [
                    NSLocalizedDescriptionKey: "the bridge returned an empty kbsync blob",
                ])
            }
            fresh = blob
        } catch {
            let detail = error.localizedDescription
            AppLog.error("kbsync generation failed: " + detail, .sap)
            fputs("[DLiPA] kbsync generation failed: " + detail + "\n", stderr)
            throw NSError(domain: "SAPSigner", code: 3, userInfo: [
                NSLocalizedDescriptionKey: detail,
            ])
        }
        AppLog.info("kbsync generated, " + String(fresh.count) + " bytes", .sap)
        Self.kbsyncCache.setObject(fresh as NSData, forKey: key)
        return fresh
    }

    /// Drops a cached blob so the next call regenerates it.
    func invalidateKBSync(dsid: String) {
        Self.kbsyncCache.removeObject(forKey: Self.cacheKey(dsid: dsid, guid: hardware.guid))
    }

    /// ent/download serialNumber: base64(54 c8 b0 a9 88 ++ guid[2:]).
    ///
    /// A fixed five-byte prefix followed by the hardware identity. This was a
    /// Go helper; it is arithmetic, not SAP protocol, so it lives here now.
    func serialNumber() throws -> String {
        guard hardware.bytes.count == 6 else {
            throw NSError(domain: "SAPSigner", code: 5, userInfo: [
                NSLocalizedDescriptionKey:
                    "the hardware identity must be 6 bytes, not \(hardware.bytes.count)",
            ])
        }
        // Upstream builds this as the five-byte prefix followed by
        // hardwareID[2:], so the first two bytes of the identity are dropped.
        // Appending all six produced a different string for every account.
        var payload = Data([0x54, 0xc8, 0xb0, 0xa9, 0x88])
        payload.append(hardware.bytes.dropFirst(2))
        return payload.base64EncodedString()
    }

    /// Set once close() has run. Tearing the session down twice would release
    /// the same emulator state again, and the account screen can reach this from
    /// both sign-out and teardown.
    private var closed = false

    func close() {
        guard !closed else { return }
        closed = true
        // Swift imports this one as a throwing close(): the BOOL return and the
        // NSError out-parameter collapse into a single throwing call, unlike the
        // other methods, which keep their explicit error pointer. A failure here
        // is not fatal -- the session is being torn down anyway -- so it is
        // logged rather than thrown out of deinit-adjacent code.
        do {
            try bridge.close()
        } catch {
            AppLog.warn("SAP close reported: " + error.localizedDescription, .sap)
        }
    }

    // MARK: kbsync cache

    private static let kbsyncCache = NSMapTable<NSString, NSData>.strongToStrongObjects()

    /// Drops every cached kbsync blob. They are keyed by dsid and guid, and a
    /// blob minted for one identity is not valid for another, so regenerating
    /// the device identity has to take them with it.
    static func forgetAllCachedKBSync() {
        kbsyncCache.removeAllObjects()
    }

    private static func cacheKey(dsid: String, guid: String) -> NSString {
        return (dsid + ":" + guid) as NSString
    }
}
