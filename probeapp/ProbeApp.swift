import Foundation
import Darwin
import UIKit

// PLAN.md step 0, as a standalone app.
//
// This exists because the main DLiPA build stopped installing under
// TrollStore, and everything that makes it awkward to install - 119 MB of
// extracted macOS binaries, the gomobile framework, a long list of
// entitlements - is irrelevant to the question being asked here.
//
// The question is narrow: does iOS already ship the components we extract
// from macOS? If it does, they are iOS binaries, and dyld can load them
// directly. That would remove chained fixups, pointer authentication, the
// macOS-only framework dependencies, and the need to emulate anything at
// all. Every difficulty in this project comes from borrowing another
// platform's binaries, so this is the first thing worth knowing.
//
// Nothing here is inferred. Each line is what the sandbox, dyld and dlsym
// actually returned on this device.

// MARK: - What to probe

private struct ProbeTarget {
    let label: String
    let path: String
    let symbols: [String]
}

/// Run first. If these will not load, dlopen is blocked in this process and
/// every "not found" below means nothing.
private let controls = [
    "/usr/lib/libSystem.B.dylib",
    "/usr/lib/libMobileGestalt.dylib",
]

/// The symbol lists come from the Go side: `machine.coreExportNames` for
/// CoreFP, and the export list in `machine.openRuntime` for
/// AppleMediaServices. Finding them here would mean the iOS copy exposes the
/// same entry points we reach through the emulator today.
private let targets: [ProbeTarget] = [
    ProbeTarget(
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
    ProbeTarget(
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
    // Listed alongside CoreFP as part of the FairPlay family. Probed in case
    // iOS names its component differently.
    ProbeTarget(label: "CoreADI",
                path: "/System/Library/PrivateFrameworks/CoreADI.framework/CoreADI",
                symbols: []),
    ProbeTarget(label: "CoreLSKD",
                path: "/System/Library/PrivateFrameworks/CoreLSKD.framework/CoreLSKD",
                symbols: []),
    ProbeTarget(label: "CommerceKit",
                path: "/System/Library/PrivateFrameworks/CommerceKit.framework/CommerceKit",
                symbols: []),
    ProbeTarget(label: "StoreFoundation",
                path: "/System/Library/PrivateFrameworks/StoreFoundation.framework/StoreFoundation",
                symbols: []),
]

/// Four 1 KB dylibs shipped inside the bundle: two platforms x two address
/// fixup eras. dlopen'ing them establishes what this device's dyld accepts,
/// which is the one thing worth knowing before any effort goes into
/// converting the 119 MB of real Apple binaries.
///
/// The interesting rows are the macOS ones. iOS-platform dylibs must work,
/// they are the control; if a macOS-platform one also loads, then the platform
/// field is not what stops us, and if only the classic-fixup one loads then
/// chained fixups are the wall.
private let fixtureNames = [
    "ios-classic",
    "ios-chained",
    "ios-arm64e",
    "macos-classic",
    "macos-chained",
    // A real converted Apple binary. It exports no probe_fixture_value, so
    // only the dlopen line matters here - that is the question.
    "commerce",
]

private func probeFixtures(_ sink: (String) -> Void) {
    sink("[FIXTURE] --- dyld acceptance matrix ---")

    for name in fixtureNames {
        let path = Bundle.main.bundlePath + "/fixtures/" + name + ".dylib"

        if let handle = dlopen(path, RTLD_NOW) {
            if let symbol = dlsym(handle, "probe_fixture_value") {
                typealias FixtureFn = @convention(c) () -> Int32
                let call = unsafeBitCast(symbol, to: FixtureFn.self)
                sink("[FIXTURE] \(name) | dlopen=OK | dlsym=OK | value=\(call())")
            } else {
                sink("[FIXTURE] \(name) | dlopen=OK | dlsym=FAIL")
            }
            _ = dlclose(handle)
        } else if let error = dlerror() {
            sink("[FIXTURE] \(name) | dlopen=FAIL \(String(cString: error))")
        } else {
            sink("[FIXTURE] \(name) | dlopen=FAIL (no dlerror)")
        }
    }
}

private func isInteresting(_ name: String) -> Bool {
    let lowered = name.lowercased()
    let needles = ["corefp", "applemedia", "commerce", "fairplay", "storefoundation"]
    for needle in needles {
        if lowered.contains(needle) {
            return true
        }
    }

    return false
}

// MARK: - Running it

private func probeOne(label: String, path: String, symbols: [String]) -> String {
    let exists = FileManager.default.fileExists(atPath: path)
    var line = "[PROBE] \(label) | exists=\(exists ? "YES" : "NO")"

    if let handle = dlopen(path, RTLD_NOW) {
        line += " | dlopen=OK"
        if !symbols.isEmpty {
            var found: [String] = []
            for symbol in symbols {
                if dlsym(handle, symbol) != nil {
                    found.append(symbol)
                }
            }
            line += " | symbols=\(found.count)/\(symbols.count)"
            for symbol in found {
                line += " \(symbol)"
            }
        }
        _ = dlclose(handle)
    } else if let error = dlerror() {
        line += " | dlopen=FAIL \(String(cString: error))"
    } else {
        line += " | dlopen=FAIL (no dlerror)"
    }

    return line
}

private func runProbe(_ sink: (String) -> Void) {
    let device = UIDevice.current
    sink("===== FRAMEWORK PROBE (PLAN.md step 0) =====")
    sink("[PROBE] device | \(device.model) \(device.systemName) \(device.systemVersion)")

    for path in controls {
        sink(probeOne(label: (path as NSString).lastPathComponent, path: path, symbols: []))
    }

    for target in targets {
        sink(probeOne(label: target.label, path: target.path, symbols: target.symbols))
    }

    // A directory listing is stronger than a per-path guess: it says what is
    // present rather than whether one guess was right. The sandbox may refuse
    // the listing, which is itself worth knowing.
    let directory = "/System/Library/PrivateFrameworks"
    do {
        let entries = try FileManager.default.contentsOfDirectory(atPath: directory)
        sink("[PROBE] PrivateFrameworks listable | entries=\(entries.count)")
        for entry in entries where isInteresting(entry) {
            sink("[PROBE]   present: \(entry)")
        }
    } catch {
        sink("[PROBE] PrivateFrameworks NOT listable | \(error.localizedDescription)")
    }

    probeFixtures(sink)

    sink("===== END FRAMEWORK PROBE =====")
}

// MARK: - App

@UIApplicationMain
final class AppDelegate: UIResponder, UIApplicationDelegate {
    var window: UIWindow?

    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        let window = UIWindow(frame: UIScreen.main.bounds)
        window.rootViewController = ProbeViewController()
        window.makeKeyAndVisible()
        self.window = window

        return true
    }
}

final class ProbeViewController: UIViewController {

    private let textView = UITextView()
    private var report = ""

    override func viewDidLoad() {
        super.viewDidLoad()

        view.backgroundColor = .white

        textView.isEditable = false
        textView.font = UIFont(name: "Menlo", size: 11) ?? UIFont.systemFont(ofSize: 11)
        textView.text = "running…"

        let copyButton = UIButton(type: .system)
        copyButton.setTitle("Copy result", for: .normal)
        copyButton.addTarget(self, action: #selector(copyResult), for: .touchUpInside)

        let shareButton = UIButton(type: .system)
        shareButton.setTitle("Share result", for: .normal)
        shareButton.addTarget(self, action: #selector(shareResult), for: .touchUpInside)

        let buttons = UIStackView(arrangedSubviews: [copyButton, shareButton])
        buttons.axis = .horizontal
        buttons.distribution = .fillEqually

        let outer = UIStackView(arrangedSubviews: [buttons, textView])
        outer.axis = .vertical
        outer.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(outer)

        let guide = view.safeAreaLayoutGuide
        NSLayoutConstraint.activate([
            outer.leadingAnchor.constraint(equalTo: guide.leadingAnchor),
            outer.trailingAnchor.constraint(equalTo: guide.trailingAnchor),
            outer.topAnchor.constraint(equalTo: guide.topAnchor),
            outer.bottomAnchor.constraint(equalTo: guide.bottomAnchor),
            buttons.heightAnchor.constraint(equalToConstant: 44),
        ])

        run()
    }

    private func run() {
        var lines: [String] = []
        runProbe { line in
            lines.append(line)
            fputs("[ProbeApp] \(line)\n", stderr)
        }

        report = lines.joined(separator: "\n")
        textView.text = report
    }

    @objc private func copyResult() {
        UIPasteboard.general.string = report
    }

    @objc private func shareResult() {
        let sheet = UIActivityViewController(activityItems: [report], applicationActivities: nil)
        sheet.popoverPresentationController?.sourceView = view
        present(sheet, animated: true, completion: nil)
    }
}
