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
        // Log the first 120 bytes so we can see what Apple actually sent
        // when PropertyListSerialization rejects it.
        let preview = String(data: data.prefix(120), encoding: .utf8)?
            .replacingOccurrences(of: "\n", with: "\\n") ?? "<binary>"
        AppLog.info("bag parse: first 120 bytes: " + preview, .network)

        // Apple's bag.xml sometimes arrives with a BOM or a leading newline
        // that confuses PropertyListSerialization. Try stripping a UTF-8 BOM
        // and any leading whitespace before the <?xml declaration.
        var trimmed = data
        if trimmed.count > 3 {
            let bytes = [UInt8](trimmed.prefix(3))
            if bytes == [0xEF, 0xBB, 0xBF] {
                trimmed = trimmed.subdata(in: 3..<trimmed.count)
                AppLog.info("bag parse: stripped UTF-8 BOM", .network)
            }
        }

        var format = PropertyListSerialization.PropertyListFormat.xml
        let plist: Any
        do {
            plist = try PropertyListSerialization.propertyList(from: trimmed, options: [], format: &format)
        } catch {
            AppLog.error("bag parse: PropertyListSerialization failed: \(error)", .network)
            // Fallback: parse the XML manually with XMLParser. Apple's bag.xml
            // is a standard plist XML, so XMLParser can read it even when
            // PropertyListSerialization's stricter validator rejects it.
            guard let parsed = BagXMLParser.parse(data: trimmed) else {
                AppLog.error("bag parse: XMLParser fallback also failed", .network)
                throw StoreError.malformedBag
            }
            AppLog.info("bag parse: XMLParser fallback succeeded, \(parsed.count) top-level keys", .network)
            return parseDict(parsed)
        }

        guard let root = plist as? [String: Any] else {
            AppLog.error("bag parse: root is not [String: Any], got \(type(of: plist))", .network)
            throw StoreError.malformedBag
        }
        let bag = (root["urlBag"] as? [String: Any]) ?? root
        return parseDict(bag)
    }

    private static func parseDict(_ bag: [String: Any]) -> StoreBag {
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

/// Minimal plist-XML parser used as a fallback when PropertyListSerialization
/// rejects Apple's bag.xml. PropertyListSerialization is stricter than the
/// plist spec (it rejects some DOCTYPE declarations and entity references),
/// while XMLParser accepts any well-formed XML. This parser only needs to
/// handle <dict>, <key>, <string>, <integer>, and <array> — the subset used
/// by bag.xml.
private final class BagXMLParser: NSObject, XMLParserDelegate {
    private var stack: [[String: Any]] = [[:]]
    private var currentKey: String?
    private var currentText = ""
    private var failed = false

    static func parse(data: Data) -> [String: Any]? {
        let parser = XMLParser(data: data)
        let delegate = BagXMLParser()
        parser.delegate = delegate
        parser.shouldProcessNamespaces = false
        guard parser.parse(), !delegate.failed else { return nil }
        return delegate.stack.first
    }

    func parser(_ parser: XMLParser, didStartElement elementName: String,
                namespaceURI: String?, qualifiedName qName: String?,
                attributes attributeDict: [String: String] = [:]) {
        currentText = ""
        switch elementName {
        case "dict":
            stack.append([:])
        case "array":
            stack.append(["__array__": true])
        case "key", "string", "integer":
            break
        default:
            break
        }
    }

    func parser(_ parser: XMLParser, foundCharacters string: String) {
        currentText += string
    }

    func parser(_ parser: XMLParser, didEndElement elementName: String,
                namespaceURI: String?, qualifiedName qName: String?) {
        let trimmed = currentText.trimmingCharacters(in: .whitespacesAndNewlines)
        switch elementName {
        case "key":
            currentKey = trimmed
        case "string":
            setValue(trimmed)
        case "integer":
            setValue(Int(trimmed) ?? trimmed)
        case "dict":
            let dict = stack.removeLast()
            setValue(dict)
        case "array":
            let dict = stack.removeLast()
            let arr = (dict["__array__"] != nil) ? [] : Array(dict.values)
            setValue(arr)
        default:
            break
        }
        currentText = ""
    }

    private func setValue(_ value: Any) {
        guard !stack.isEmpty else { return }
        let isTopArray = (stack.last?["__array__"] != nil)
        if isTopArray {
            // Arrays don't use keys; we don't need array contents for bag.xml
            // parsing, so just record a placeholder.
            return
        }
        if let key = currentKey {
            stack[stack.count - 1][key] = value
            currentKey = nil
        }
    }

    func parser(_ parser: XMLParser, parseErrorOccurred parseError: Error) {
        AppLog.error("bag XMLParser error: \(parseError)", .network)
        failed = true
    }
}

enum StoreError: LocalizedError {
    case noBagEndpoint
    case malformedBag
    case signingFailed
    case httpError(Int, String)
    case failureType(String, String)
    case twoFactorRequired

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
        case .twoFactorRequired:
            return NSLocalizedString("alert_2f_auth_message", comment: "2FA required")
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
        case .twoFactorRequired:
            return "Apple requires 2FA verification code"
        }
    }
}
