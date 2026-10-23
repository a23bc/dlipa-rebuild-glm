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

/// The HTTP round trip between the two exchange legs.
///
/// The guest is synchronous and has no network stack, so the C side calls
/// back into this while it is inside sap_guest_handshake. The setup message is
/// posted as an XML plist under sign-sap-setup-buffer, and the reply is the
/// same key in the response.
final class SAPTransport {
    private let setupURL: URL

    init(setupURL: String) {
        self.setupURL = URL(string: setupURL) ?? URL(string: "about:blank")!
    }

    func post(request: Data) throws -> Data {
        let envelope: [String: Any] = ["sign-sap-setup-buffer": request]
        let body = try PropertyListSerialization.data(
            fromPropertyList: envelope, format: .xml, options: 0)

        var urlRequest = URLRequest(url: setupURL)
        urlRequest.httpMethod = "POST"
        urlRequest.httpBody = body
        urlRequest.setValue("application/x-plist", forHTTPHeaderField: "Content-Type")
        urlRequest.setValue("Configurator/2.17 (Macintosh; 16G29; Mac OS X 10.12.6)",
                            forHTTPHeaderField: "User-Agent")

        let semaphore = DispatchSemaphore(value: 0)
        var payload: Data?
        var failure: Error?
        URLSession.shared.dataTask(with: urlRequest) { data, response, error in
            defer { semaphore.signal() }
            if let error {
                failure = error
                return
            }
            if let http = response as? HTTPURLResponse, http.statusCode != 200 {
                failure = NSError(domain: "SAPTransport", code: 1, userInfo: [
                    NSLocalizedDescriptionKey: "apple returned \(http.statusCode)",
                ])
                return
            }
            payload = data
        }.resume()
        semaphore.wait()

        if let failure { throw failure }
        guard let payload,
              let plist = try PropertyListSerialization
                .propertyList(from: payload, options: [], format: nil)
                as? [String: Any],
              let reply = plist["sign-sap-setup-buffer"] as? Data,
              !reply.isEmpty else {
            throw NSError(domain: "SAPTransport", code: 2, userInfo: [
                NSLocalizedDescriptionKey:
                    "the reply has no usable sign-sap-setup-buffer",
            ])
        }
        return reply
    }
}

/// The C callback the guest uses to reach the transport.
///
/// It must not capture anything, so the transport arrives through the userdata
/// pointer that was installed in sap_guest_config. Returning non-zero aborts
/// the chain and surfaces as a handshake error.
private func sapTransportPost(_ request: UnsafePointer<UInt8>?,
                              _ requestLength: Int,
                              _ reply: UnsafeMutablePointer<UInt8>?,
                              _ replyCapacity: Int,
                              _ replyLength: UnsafeMutablePointer<Int>?,
                              _ userdata: UnsafeMutableRawPointer?) -> Int32 {
    guard let userdata, let request, let reply, let replyLength else {
        return -1
    }
    let transport = Unmanaged<SAPTransport>.fromOpaque(userdata).takeUnretainedValue()
    do {
        let payload = Data(bytes: request, count: requestLength)
        let response = try transport.post(request: payload)
        guard response.count <= replyCapacity else { return -2 }
        response.copyBytes(to: reply, count: response.count)
        replyLength.pointee = response.count
        return 0
    } catch {
        AppLog.error("SAP transport FAILED: " + error.localizedDescription, .sap)
        return -3
    }
}

/// Owns the SAP session. Create once after login and share for the whole
/// session; the session is stateful, so re-signing is required after any
/// redirect.
final class SAPSigner {
    /// The Unicorn-backed guest. Owns the X64I container and the emulator.
    private let guest: OpaquePointer
    /// Held for the session: the post callback runs while the guest is inside
    /// sap_guest_handshake, and a deallocated transport would be a use-after-free.
    private let transport: SAPTransport
    let hardware: HardwareIdentity

    init(setupURL: String, certURL: String, version: Int32, hardware: HardwareIdentity) throws {
        // The guest needs three things the old Go bridge fetched for it: the
        // container, the setup certificate and a transport for the one HTTP
        // round trip between the two exchange legs.
        let imagePath = try SAPSigner.imagePath()
        let certificate = try SAPSigner.fetchCertificate(certURL: certURL)
        let transport = SAPTransport(setupURL: setupURL)
        self.hardware = hardware

        var config = sap_guest_config()
        config.hardware_id_len = hardware.bytes.count
        var errorBuffer = [CChar](repeating: 0, count: 512)

        // The pointers below have to outlive the call, so the buffers are
        // held by this scope rather than created inline.
        let guestPointer: OpaquePointer? = imagePath.withCString { imageCString in
            certificate.withUnsafeBytes { certificateBytes in
                hardware.bytes.withUnsafeBytes { hardwareBytes in
                    config.image_path = imageCString
                    config.certificate = certificateBytes.bindMemory(
                        to: UInt8.self).baseAddress
                    config.certificate_len = certificate.count
                    config.hardware_id = hardwareBytes.bindMemory(
                        to: UInt8.self).baseAddress
                    config.post = sapTransportPost
                    config.userdata = Unmanaged.passUnretained(transport).toOpaque()
                    return sap_guest_new(&config, &errorBuffer,
                                         errorBuffer.count)
                }
            }
        }

        guard let guestPointer else {
            let detail = String(cString: errorBuffer)
            AppLog.error("SAP guest load FAILED: " + detail, .sap)
            fputs("[DLiPA] SAP guest load FAILED: " + detail + "\n", stderr)
            throw NSError(domain: "SAPSigner", code: 1, userInfo: [
                NSLocalizedDescriptionKey: detail,
            ])
        }
        self.guest = guestPointer
        // Kept alive for the whole session: the post callback runs while the
        // guest is inside sap_guest_handshake.
        self.transport = transport

        if sap_guest_handshake(guest, &errorBuffer, errorBuffer.count) != 0 {
            let detail = String(cString: errorBuffer)
            sap_guest_free(guest)
            AppLog.error("SAP handshake FAILED: " + detail, .sap)
            fputs("[DLiPA] SAP handshake FAILED: " + detail + "\n", stderr)
            throw NSError(domain: "SAPSigner", code: 2, userInfo: [
                NSLocalizedDescriptionKey: detail,
            ])
        }

        var stats = sap_guest_stats()
        sap_guest_get_stats(guest, &stats)
        AppLog.info("SAP signer ready, hardware " + hardware.guid
            + ", cert v\(stats.cert_version) state \(stats.cert_state)"
            + ", reply v\(stats.reply_version) state \(stats.reply_state)", .sap)
    }

    /// The value for the X-Apple-ActionSignature header.
    func signatureHeaderValue(for body: Data) throws -> String {
        var errorBuffer = [CChar](repeating: 0, count: 512)
        var header: UnsafeMutablePointer<CChar>?
        let status = body.withUnsafeBytes { bodyBytes in
            sap_guest_sign(guest,
                           bodyBytes.bindMemory(to: UInt8.self).baseAddress,
                           body.count, &header, &errorBuffer, errorBuffer.count)
        }
        guard status == 0, let header else {
            throw NSError(domain: "SAPSigner", code: 4, userInfo: [
                NSLocalizedDescriptionKey: String(cString: errorBuffer),
            ])
        }
        defer { free(header) }
        return String(cString: header)
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
        var payload = Data([0x54, 0xc8, 0xb0, 0xa9, 0x88])
        payload.append(hardware.bytes.prefix(6))
        return payload.base64EncodedString()
    }

    func close() {
        // sap_guest_free releases the emulator, the container and the
        // certificate. Calling it twice would double-free, so the handle is
        // only ever freed from here and the object is not reused after.
        sap_guest_free(guest)
    }

    // MARK: staging

    /// The X64I container produced offline by sapbridge/cmd/x86image.
    ///
    /// It ships in the bundle next to the Apple binaries it was built from.
    /// Both names are tried because the staging scripts have used each.
    private static func imagePath() throws -> String {
        for name in ["commerce_native.bin", "commerce.x64i"] {
            if let url = Bundle.main.url(forResource: (name as NSString)
                .deletingPathExtension, withExtension: (name as NSString).pathExtension) {
                return url.path
            }
        }
        throw NSError(domain: "SAPSigner", code: 10, userInfo: [
            NSLocalizedDescriptionKey: "the SAP guest image is missing from the bundle",
        ])
    }

    /// Fetches and decodes the setup certificate: the plist entry
    /// sign-sap-setup-cert, which is the input to the first exchange leg.
    private static func fetchCertificate(certURL: String) throws -> Data {
        guard let url = URL(string: certURL) else {
            throw NSError(domain: "SAPSigner", code: 11, userInfo: [
                NSLocalizedDescriptionKey: "bad certificate URL " + certURL,
            ])
        }
        var request = URLRequest(url: url)
        request.setValue("Configurator/2.17 (Macintosh; 16G29; Mac OS X 10.12.6)",
                         forHTTPHeaderField: "User-Agent")

        // Synchronous on purpose: the caller is already on a background queue
        // and the guest cannot proceed until it has the certificate.
        let semaphore = DispatchSemaphore(value: 0)
        var payload: Data?
        var failure: Error?
        URLSession.shared.dataTask(with: request) { data, response, error in
            defer { semaphore.signal() }
            if let error {
                failure = error
                return
            }
            if let http = response as? HTTPURLResponse, http.statusCode != 200 {
                failure = NSError(domain: "SAPSigner", code: 12, userInfo: [
                    NSLocalizedDescriptionKey: "apple returned \(http.statusCode)",
                ])
                return
            }
            payload = data
        }.resume()
        semaphore.wait()

        if let failure { throw failure }
        guard let payload else {
            throw NSError(domain: "SAPSigner", code: 13, userInfo: [
                NSLocalizedDescriptionKey: "empty certificate response",
            ])
        }
        guard let plist = try PropertyListSerialization
            .propertyList(from: payload, options: [], format: nil)
            as? [String: Any],
            let certificate = plist["sign-sap-setup-cert"] as? Data,
            !certificate.isEmpty else {
            throw NSError(domain: "SAPSigner", code: 14, userInfo: [
                NSLocalizedDescriptionKey:
                    "the plist has no usable sign-sap-setup-cert",
            ])
        }
        return certificate
    }

    // MARK: kbsync cache

    private static let kbsyncCache = NSMapTable<NSString, NSData>.strongToStrongObjects()

    private static func cacheKey(dsid: String, guid: String) -> NSString {
        return (dsid + ":" + guid) as NSString
    }
}
