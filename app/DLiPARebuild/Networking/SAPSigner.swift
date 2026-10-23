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
        SapbridgeGuidFromHardware(bytes)
    }

    /// A stable 6-byte identity.
    ///
    /// iOS exposes no MAC address, so the first 6 bytes of the vendor
    /// identifier UUID string are used. Stable across launches, which matters
    /// because a cached kbsync blob is only valid for its identity.
    static func stable() -> HardwareIdentity {
        let seed = UIDevice.current.identifierForVendor?.uuidString ?? "dlipa-fallback"
        let data = Data(seed.utf8)
        let digest = Array(SHA256.hash(data: data))
        return HardwareIdentity(bytes: Data(digest.prefix(6)))
    }
}

/// Owns the SAP session. Create once after login and share for the whole
/// session; the session is stateful, so re-signing is required after any
/// redirect.
final class SAPSigner {
    private let signer: SapbridgeSigner
    let hardware: HardwareIdentity

    init(setupURL: String, certURL: String, version: Int32, hardware: HardwareIdentity) throws {
        var error: NSError?
        guard let s = SapbridgeNew(setupURL, certURL, version, hardware.bytes, &error),
            error == nil else {
            // The Go side wraps every entry point with recover(), so a panic
            // deep in the SAP/Unicorn stack surfaces here as an NSError whose
            // localizedDescription contains "Go panic in SAP handshake: <value>"
            // plus a stack trace. Log every byte of it so it lands in the
            // in-app log view, the shareable log, and OSLog (syslog).
            let detail = error?.localizedDescription
                ?? error?.localizedFailureReason
                ?? error?.domain
                ?? "unknown error"
            AppLog.error("SAP handshake FAILED: " + detail, .sap)
            // Also dump to stderr in case OSLog redaction hides part of it;
            // stderr lines starting with [SAP] are easy to grep in syslog.
            fputs("[DLiPA] SAP handshake FAILED: " + detail + "\n", stderr)
            throw error ?? NSError(domain: "SAPSigner", code: 1, userInfo: nil)
        }
        self.signer = s
        self.hardware = hardware
        AppLog.info("SAP signer ready, hardware " + hardware.guid, .sap)
    }

    /// The value for the X-Apple-ActionSignature header.
    func signatureHeaderValue(for body: Data) throws -> String {
        var error: NSError?
        let value = signer.signatureHeaderValue(body, error: &error)
        if let error { throw error }
        return value
    }

    /// The FairPlay kbsync blob required by ent/download.
    ///
    /// Generating a blob spins up the Unicorn guest and the Apple binaries,
    /// which is expensive, and the blob is stable for a given account and
    /// device. So it is cached and reused. A blob Apple rejected is discarded
    /// so the next call regenerates it; a fresh blob is never retried.
    func kbsync(dsid: String) throws -> Data {
        let key = Self.cacheKey(dsid: dsid, guid: hardware.guid)
        if let cached = Self.kbsyncCache.object(forKey: key) {
            return cached as Data
        }
        if let cached = Self.kbsyncCache.object(forKey: key) {
            AppLog.debug("kbsync reused from cache", .sap)
            return cached as Data
        }
        var error: NSError?
        // Generating the blob runs the Unicorn guest and the Apple binaries,
        // so a failure here is worth naming precisely. The Go side wraps
        // this in recover() too, so any panic surfaces as an NSError here
        // instead of killing the process.
        guard let fresh = SapbridgeKBSync(hardware.bytes, dsid, &error) else {
            let detail = error?.localizedDescription ?? "unknown"
            AppLog.error("kbsync generation failed: " + detail, .sap)
            fputs("[DLiPA] kbsync generation failed: " + detail + "\n", stderr)
            throw error ?? NSError(domain: "SAPSigner", code: 3, userInfo: nil)
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
    func serialNumber() throws -> String {
        var error: NSError?
        let value = SapbridgeSerialNumber(hardware.bytes, &error)
        if let error { throw error }
        return value
    }

    func close() {
        // The gomobile-generated close: method is declared as
        //   - (BOOL)close:(NSError **)error;
        // in the bridging header. Swift imports a method whose trailing
        // NSError ** parameter is named "error" as a throwing method with no
        // arguments, so the correct call is `try signer.close()`. The earlier
        // implementation used perform(Selector("close:"), with: error), which
        // passed an NSError * where the method expects an NSError **; on the
        // failure path gomobile would write through the (nil) pointer and
        // segfault.
        do {
            try signer.close()
        } catch {
            AppLog.error("close failed: " + error.localizedDescription, .sap)
        }
    }

    // MARK: kbsync cache

    private static let kbsyncCache = NSMapTable<NSString, NSData>.strongToStrongObjects()

    private static func cacheKey(dsid: String, guid: String) -> NSString {
        return (dsid + ":" + guid) as NSString
    }
}
