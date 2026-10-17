import Foundation

/// Endpoints discovered in `bag.xml`.
///
/// The plist keys carry a `loc-` prefix on the wire, which is stripped here.
struct StoreBag {
    var authenticateAccount: String?
    var signSapSetup: String?
    var signSapSetupCert: String?
    var signSapVersion: Int32 = 0
    /// Apple now serves this as `downloaddispatch.itunes.apple.com/.../ent/download`.
    var volumeStoreDownloadProduct: String?
    var redownloadProduct: String?
    var updateProduct: String?

    var hasSAPConfiguration: Bool {
        guard let setup = signSapSetup, let cert = signSapSetupCert else { return false }
        return !setup.isEmpty && !cert.isEmpty && signSapVersion == 200
    }

    /// Parses the bag. Accepts either a top-level `urlBag` dict or a flat dict.
    static func parse(xml data: Data) throws -> StoreBag {
        var format = PropertyListSerialization.PropertyListFormat.xml
        let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: &format)
        guard let root = plist as? [String: Any] else {
            throw StoreError.malformedBag
        }
        let bag = (root["urlBag"] as? [String: Any]) ?? root

        var result = StoreBag()
        result.authenticateAccount = string(bag["authenticateAccount"])
        result.signSapSetup = string(bag["sign-sap-setup"])
        result.signSapSetupCert = string(bag["sign-sap-setup-cert"])
        result.volumeStoreDownloadProduct = string(bag["volumeStoreDownloadProduct"])
        result.redownloadProduct = string(bag["redownloadProduct"])
        result.updateProduct = string(bag["updateProduct"])
        result.signSapVersion = Int32(string(bag["sign-sap-version"]) ?? "") ?? 0
        return result
    }

    private static func string(_ value: Any?) -> String? {
        guard let s = value as? String, !s.isEmpty else { return nil }
        // Accept both the raw and the loc- prefixed form.
        if s.hasPrefix("loc-") { return String(s.dropFirst(4)) }
        return s
    }
}

enum StoreError: LocalizedError {
    case noBagEndpoint
    case malformedBag
    case signingFailed
    case httpError(Int, String)
    case failureType(String, String)

    /// User-facing message. Specific detail goes to the log so the alert stays
    /// short and localised the way the original app does it.
    var errorDescription: String? {
        switch self {
        case .noBagEndpoint, .malformedBag, .signingFailed:
            return NSLocalizedString("toast_something_wrong", comment: "Generic failure")
        case .httpError(let code, let body):
            let fmt = NSLocalizedString("Apple returned HTTP %d: %@", comment: "HTTP failure")
            return String(format: fmt, code, body)
        case .failureType(let type, let message):
            // Apple reports numeric failure types; the .strings files carry the
            // named keys, so translate the number first. Unknown values fall
            // back to the raw type.
            let key = StoreError.failureKey(for: type)
            if message.isEmpty {
                return NSLocalizedString(key, comment: "Apple failure type")
            }
            return NSLocalizedString(key, value: message, comment: "Apple failure type with message")
        }
    }

    /// Maps Apple numeric failure types to the localisation keys present in the
    /// .strings files. Mirrors ipatool FailureType constants.
    static func failureKey(for type: String) -> String {
        switch type {
        case "-5000": return "ap_invalid_credentials"
        case "2034":  return "ap_password_token_expired"
        case "2042":  return "ap_resignin"
        case "9610":  return "ap_license_required"
        case "2059":  return "ap_item_temporarily_unavailable"
        case "5002":  return "ap_already_have_this_app"
        case "1008":  return "ap_device_verification_failed"
        default:      return type
        }
    }

    /// Detailed text for the log, not for the alert.

    var detail: String {
        switch self {
        case .noBagEndpoint:
            return "bag did not advertise a download endpoint"
        case .malformedBag:
            return "bag could not be parsed"
        case .signingFailed:
            return "the request body could not be signed"
        case .httpError(let code, let body):
            return "HTTP \(code): \(body.prefix(500))"
        case .failureType(let type, let message):
            return type + (message.isEmpty ? "" : ": \(message)")
        }
    }
}
