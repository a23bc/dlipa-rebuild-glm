import Darwin
import Foundation
import ObjectiveC.runtime

/// The one question that decides how anisette gets implemented here: can this
/// process obtain it from iOS itself, or does it have to be computed the way
/// kbsync is -- inside the emulated macOS framework?
///
/// ## Why this is asked before anything is written
///
/// Sign-in stopped working on 2026-11-07 and the reason is a header: the store
/// endpoints now require the anisette pair (`X-Apple-I-MD`, `X-Apple-I-MD-M`,
/// sent on store requests as `X-Apple-AMD` / `X-Apple-AMD-M`). Those two values
/// are produced by AppleDeviceIdentity, and there are exactly two ways to get
/// them here. Either the device's own framework will hand them to us, which is
/// a few hundred lines, or we emulate the identity service the way we already
/// emulate the store framework, which is upstream's route and is measured in
/// thousands of lines across four emulated runtimes.
///
/// The two routes cost a factor of twenty, and no amount of reading the macOS
/// side can tell which one is open on an iPhone. This answers it from the
/// device, with nothing but the runtime's own lookup functions.
///
/// ## What each line means
///
/// - `exists=` / `dlopen=` -- whether the sandbox lets the image be seen and
///   loaded at all. A load failure makes every later line about that image moot,
///   which is why both are printed even when the class list is empty.
/// - `classes=` -- the Objective-C classes that image actually exports, filtered
///   to the ones whose names mention anisette/OTP/ADI. Names are evidence; a
///   guessed selector is not.
/// - `methods=` -- for a class that loaded, the selectors it implements. This is
///   the line that matters: an anisette class is useless without an entry point
///   that returns the proof.
/// - `symbols=` -- the C entry points tried with `dlsym`. These are candidate
///   names from published implementations of the same problem; a miss here is
///   weaker evidence than a miss on the class list, because the names differ
///   across generations of the framework.
///
/// Nothing in the output is inferred. If the conclusion looks ambiguous, print
/// it anyway -- an honest `0/6` is worth more than a guess about why.
enum AnisetteProbe {
    private struct Image {
        let label: String
        let path: String
    }

    private static let images = [
        Image(label: "AppleDeviceIdentity",
              path: "/System/Library/PrivateFrameworks/AppleDeviceIdentity.framework/AppleDeviceIdentity"),
        Image(label: "CoreADI",
              path: "/System/Library/PrivateFrameworks/CoreADI.framework/CoreADI"),
        Image(label: "AppleMediaServices",
              path: "/System/Library/PrivateFrameworks/AppleMediaServices.framework/AppleMediaServices"),
        Image(label: "AuthKit",
              path: "/System/Library/PrivateFrameworks/AuthKit.framework/AuthKit"),
        // The two that historically held the `aos_anisette` C entry points and
        // the store's own anisette client. The identity library is not on this
        // system, so if the proof can be made here at all, it is made in one of
        // these two -- or in neither, which is the answer that sends us to
        // emulating the identity service.
        Image(label: "AOSKit",
              path: "/System/Library/PrivateFrameworks/AOSKit.framework/AOSKit"),
        Image(label: "StoreServices",
              path: "/System/Library/PrivateFrameworks/StoreServices.framework/StoreServices"),
        Image(label: "AppleIDAuthSupport",
              path: "/System/Library/PrivateFrameworks/AppleIDAuthSupport.framework/AppleIDAuthSupport"),
    ]

    /// Names that appear in the identity service's C interface, as published
    /// implementations of this problem call it. A miss here is weaker evidence
    /// than a miss on the class list: these names differ across generations of
    /// the frameworks, and only a hit proves presence.
    private static let symbols = [
        "adi_init",
        "adi_provision",
        "adi_set_provisioning_info",
        "adi_set_system_info",
        "adi_set_pin",
        "adi_get_random",
        "adi_set_otp",
        "aos_anisette_getOTPAndMITMForDSID",
        "aos_anisette_provisionWithResponseData",
        "aos_anisette_set_provisioning_info",
        "aos_anisette_machine_identifier",
    ]

    private static let needles = ["anis", "otp", "adi", "deviceidentity", "mitm", "provision"]

    /// The selectors worth their encoding: the ones that would be called to get
    /// or provision the proof. Printing the encoding is what makes the next
    /// package's call written from evidence rather than guessed -- a block
    /// argument of the wrong arity is a crash, not a failed request.
    private static let interesting = ["anisette", "otp", "mitm", "provision", "routinginfo"]

    static func run() {
        emit("===== ANISETTE PROBE =====")

        for image in images {
            probe(image)
        }

        mappedImages()

        emit("===== END ANISETTE PROBE =====")
    }

    private static let imageNeedles = ["anisette", "deviceidentity", "aoskit", "adi.framework",
                                       "storeservices", "authkit", "appleidauth"]

    /// What this process already has mapped. A path in this list is reachable
    /// without a dlopen guess, which matters because the identity library turned
    /// out to be on neither of the paths dyld tried -- so if the proof exists on
    /// iOS at all, it lives in an image that is already loaded or in one of the
    /// frameworks above.
    private static func mappedImages() {
        var hits: [String] = []
        let total = _dyld_image_count()

        for index in 0 ..< total {
            guard let raw = _dyld_get_image_name(index) else { continue }

            let path = String(cString: raw)

            if imageNeedles.contains(where: { path.lowercased().contains($0) }) {
                hits.append(path)
            }
        }

        emit("[ANISETTE] mapped images matching needles=\(hits.count)/\(total)")

        for path in hits.prefix(12) {
            emit("[ANISETTE]   mapped: " + path)
        }
    }

    private static func probe(_ image: Image) {
        let exists = FileManager.default.fileExists(atPath: image.path)
        var line = "[ANISETTE] \(image.label) | exists=\(exists ? "YES" : "NO")"
        var handle: UnsafeMutableRawPointer?

        if let loaded = dlopen(image.path, RTLD_NOW) {
            handle = loaded
            line += " | dlopen=OK"
        } else if let error = dlerror() {
            line += " | dlopen=FAIL \(String(cString: error))"
        } else {
            line += " | dlopen=FAIL (no dlerror)"
        }

        emit(line)

        // A symbol search is only meaningful on a loaded image: reporting 0/7
        // after a dlopen failure would read as "the entry points are missing"
        // when what is missing is the image.
        if let handle {
            let found = symbols.filter { dlsym(handle, $0) != nil }

            emit("[ANISETTE]   \(image.label) symbols=\(found.count)/\(symbols.count) "
                 + found.joined(separator: " "))
            classes(from: image)
        } else {
            emit("[ANISETTE]   \(image.label) symbols=not-looked-up (image not loaded)")
            emit("[ANISETTE]   \(image.label) classes=not-looked-up (image not loaded)")
        }
    }

    /// The classes the loaded image exports, filtered, and the selectors of the
    /// ones that look like the entry point we need.
    private static func classes(from image: Image) {
        var count: UInt32 = 0
        let names = objc_copyClassNamesForImage(image.path, &count)

        guard let names else {
            emit("[ANISETTE]   \(image.label) classes=unavailable")
            return
        }

        defer { free(UnsafeMutableRawPointer(names)) }

        var matches: [String] = []

        for index in 0 ..< Int(count) {
            let name = String(cString: names[index])

            if needles.contains(where: { name.lowercased().contains($0) }) {
                matches.append(name)
            }
        }

        emit("[ANISETTE]   \(image.label) classes=\(matches.count)/\(count)")

        for name in matches.prefix(12) {
            emit("[ANISETTE]     \(name) methods=" + selectors(of: name))
        }
    }

    private static func selectors(of className: String) -> String {
        guard let cls = NSClassFromString(className) else { return "class-unavailable" }

        var count: UInt32 = 0
        let methods = class_copyMethodList(cls, &count)

        guard let methods else { return "none" }

        defer { free(UnsafeMutableRawPointer(methods)) }

        var shaped: [String] = []
        var plain: [String] = []

        for index in 0 ..< Int(count) {
            let method = methods[index]
            let name = NSStringFromSelector(method_getName(method))
            plain.append(name)

            if interesting.contains(where: { name.lowercased().contains($0) }) {
                shaped.append(name + " :: " + String(cString: method_getTypeEncoding(method)))
            }
        }

        if !shaped.isEmpty {
            return shaped.prefix(8).joined(separator: " | ") + " (matched \(shaped.count)/\(count))"
        }

        return plain.prefix(10).joined(separator: ", ") + (count > 10 ? " … (\(count))" : "")
    }

    /// Written to both sinks, like the framework probe: AppLog so it reaches
    /// Share log, stderr so the flight recorder keeps it if this launch dies.
    private static func emit(_ message: String) {
        AppLog.error(message, .app)
        fputs("[DLiPA] \(message)\n", stderr)
    }
}
