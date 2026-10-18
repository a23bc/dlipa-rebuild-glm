import Foundation
import Darwin

/// PLAN.md step 0: does iOS already ship the components we currently borrow
/// from macOS?
///
/// ## Why this is the first thing to check
///
/// Everything in this project starts from four binaries extracted out of
/// macOS 27.0.1 (CoreFP, AppleMediaServices, commerce, CoreFP.icxs). Every
/// problem we have been fighting is a *consequence of them belonging to
/// another platform*:
///
/// - chained fixups (a macOS 13+ format iOS 15's dyld does not read)
/// - pointer authentication (arm64e instructions A10 cannot run)
/// - dependencies on frameworks that only exist on macOS
/// - and, above all, the need to emulate them, which needs executable
///   memory that iOS will not give us
///
/// If iOS ships the same components, they are iOS binaries. dyld can load
/// them straight from its own shared cache, with no fixups to convert, no
/// PAC to strip and no missing frameworks. That is why this runs before
/// anything else: a single YES here changes every decision after it.
///
/// ## What it reports
///
/// Nothing here is inferred. Each line is what the sandbox, dyld and dlsym
/// actually returned on this device:
///
/// - `exists=` — whether the sandbox lets us see the path at all
/// - `dlopen=` — whether dyld will load it, with its own error text
/// - `symbols=` — whether the exact entry points our Go bridge resolves
///   out of the macOS binaries are also exported here
///
/// Two controls run first. If `libSystem.B.dylib` will not load, then
/// dlopen is blocked in this process and every "not found" below is
/// meaningless.
enum FrameworkProbe {

    // MARK: - Controls

    /// Must succeed. If it does not, nothing below can be trusted.
    private static let controls = [
        "/usr/lib/libSystem.B.dylib",
        "/usr/lib/libMobileGestalt.dylib",
    ]

    // MARK: - Targets

    /// The symbol lists are copied from the Go side:
    /// `machine.coreExportNames` for CoreFP, and the export list in
    /// `machine.openRuntime` for AppleMediaServices. Matching them here
    /// would mean the iOS copy exposes the same entry points we call
    /// through the emulator today.
    private struct Target {
        let label: String
        let path: String
        let symbols: [String]
    }

    private static let targets: [Target] = [
        Target(
            label: "CoreFP",
            path: "/System/Library/PrivateFrameworks/CoreFP.framework/CoreFP",
            symbols: [
                "_WIn9UJ86JKdV4dM",
                "_X46O5IeS",
                "_YlCJ3lg",
                "_dku592fbFAj",
                "_fdjkDSAFjklaf2s",
                "_lxpgvVMLd0S7uRl",
            ]
        ),
        Target(
            label: "AppleMediaServices",
            path: "/System/Library/PrivateFrameworks/AppleMediaServices.framework/AppleMediaServices",
            symbols: [
                "_cp2g1b9ro",
                "_Mib5yocT",
                "_Fc3vhtJDvr",
                "_IPaI1oem5iL",
                "_jEHf8Xzsv8K",
            ]
        ),
        // Listed with CoreFP as part of the FairPlay family. Probed in case
        // iOS names its SAP component differently.
        Target(label: "CoreADI",
               path: "/System/Library/PrivateFrameworks/CoreADI.framework/CoreADI",
               symbols: []),
        Target(label: "CoreLSKD",
               path: "/System/Library/PrivateFrameworks/CoreLSKD.framework/CoreLSKD",
               symbols: []),
        Target(label: "CommerceKit",
               path: "/System/Library/PrivateFrameworks/CommerceKit.framework/CommerceKit",
               symbols: []),
        Target(label: "StoreFoundation",
               path: "/System/Library/PrivateFrameworks/StoreFoundation.framework/StoreFoundation",
               symbols: []),
    ]

    // MARK: - Entry point

    static func run() {
        emit("===== FRAMEWORK PROBE (PLAN.md step 0) =====")

        for path in controls {
            probe(label: URL(fileURLWithPath: path).lastPathComponent,
                  path: path,
                  symbols: [])
        }

        for target in targets {
            probe(label: target.label, path: target.path, symbols: target.symbols)
        }

        listPrivateFrameworks()

        emit("===== END FRAMEWORK PROBE =====")
    }

    // MARK: - Probes

    private static func probe(label: String, path: String, symbols: [String]) {
        let exists = FileManager.default.fileExists(atPath: path)
        var line = "[PROBE] \(label) | exists=\(exists ? "YES" : "NO")"

        if let handle = dlopen(path, RTLD_NOW) {
            line += " | dlopen=OK"
            if !symbols.isEmpty {
                var found: [String] = []
                for name in symbols {
                    if dlsym(handle, name) != nil {
                        found.append(name)
                    }
                }
                line += " | symbols=\(found.count)/\(symbols.count)"
                for name in found {
                    line += " \(name)"
                }
            }
            _ = dlclose(handle)
        } else if let error = dlerror() {
            line += " | dlopen=FAIL \(String(cString: error))"
        } else {
            line += " | dlopen=FAIL (no dlerror)"
        }

        emit(line)
    }

    /// A directory listing is stronger evidence than a per-path guess: it
    /// tells us what is present rather than whether one guess was right.
    /// The sandbox may refuse the listing, which is itself worth knowing.
    private static func listPrivateFrameworks() {
        let directory = "/System/Library/PrivateFrameworks"

        do {
            let entries = try FileManager.default.contentsOfDirectory(atPath: directory)
            emit("[PROBE] PrivateFrameworks listable | entries=\(entries.count)")

            for name in entries where isInteresting(name) {
                emit("[PROBE]   present: \(name)")
            }
        } catch {
            emit("[PROBE] PrivateFrameworks NOT listable | \(error.localizedDescription)")
        }
    }

    private static func isInteresting(_ name: String) -> Bool {
        let needles = ["corefp", "applemedia", "commerce", "fairplay", "storefoundation"]
        let lowered = name.lowercased()

        return needles.contains { lowered.contains($0) }
    }

    // MARK: - Output

    /// Written to both sinks: AppLog so it is visible behind Share log, and
    /// stderr so the flight recorder keeps it if this launch dies later.
    private static func emit(_ message: String) {
        AppLog.error(message, .app)
        fputs("[DLiPA] \(message)\n", stderr)
    }
}
