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

// Stage 1 of the TCI route. The emulator either interprets a few x86-64
// instructions on this device or it does not; everything else about the SAP
// port depends on that answer, so it is asked before any of it is written.
//
// The report opens with a control that tries to allocate exactly the memory
// the JIT build needs. If that fails and the guest still runs, the interpreter
// provably did not use executable memory - which is the whole point.
private func probeTCI(_ sink: (String) -> Void) {
    var buffer = [CChar](repeating: 0, count: 8192)
    tciprobe_report(&buffer, buffer.count)
    // Split by hand: enumerateLines takes an escaping closure, and sink is
    // non-escaping, which swiftc rejects at the capture.
    let text = String(cString: buffer)
    for line in text.split(separator: "\n") {
        sink(String(line))
    }
}

private func runProbe(_ sink: (String) -> Void) {
    // Say which build this is, first thing. The IPA name is derived from the
    // executable's hash, so a run that only changed bundled fixtures produced
    // an identically named file and an old install was indistinguishable from
    // a new one. This makes every report self-identifying.
    let buildIDURL = Bundle.main.bundleURL.appendingPathComponent("BuildID.txt")
    let buildID = (try? String(contentsOf: buildIDURL, encoding: .utf8))?
        .trimmingCharacters(in: .whitespacesAndNewlines) ?? "unknown"
    sink("[BUILD] \(buildID.replacingOccurrences(of: "\n", with: " "))")

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

    probeTCI(sink)

    // Bounded by Unicorn's own timeout, so this cannot hang the app even if
    // the interpreter turns out to be pathologically slow.
    var bench = [CChar](repeating: 0, count: 4096)
    benchprobe_report(&bench, bench.count)
    for line in String(cString: bench).split(separator: "\n") {
        sink(String(line))
    }

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

        // Its own button because a refusal is a SIGKILL: if it ran as part of
        // the main report, a decision not to allow generated code would take
        // the entire report down with it.
        let jitButton = UIButton(type: .system)
        jitButton.setTitle("Test JIT", for: .normal)
        jitButton.addTarget(self, action: #selector(testJIT), for: .touchUpInside)

        // Loading 15 MB of guest image and running it can take seconds, and a
        // wrong address in the loader could fault. Kept off the main report
        // for the same reason as the JIT probe.
        let coreFPButton = UIButton(type: .system)
        coreFPButton.setTitle("Test CoreFP", for: .normal)
        coreFPButton.addTarget(self, action: #selector(testCoreFP), for: .touchUpInside)

        // The one that asks the actual question: call CommerceKit's SAP init
        // the way the driver does, rather than poking exports with zeroes.
        let sapButton = UIButton(type: .system)
        sapButton.setTitle("Test SAP", for: .normal)
        sapButton.addTarget(self, action: #selector(testSAP), for: .touchUpInside)

        let buttons = UIStackView(arrangedSubviews: [copyButton, shareButton, jitButton, coreFPButton, sapButton])
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

    // Appends rather than replaces, so the main report survives either way.
    @objc private func testJIT() {
        var buffer = [CChar](repeating: 0, count: 4096)
        jitprobe_report(&buffer, buffer.count)
        let text = String(cString: buffer)
        report += "\n" + text
        textView.text = report
        UIPasteboard.general.string = report
    }

    // Runs Apple's own x86-64 CoreFP under the interpreter and stops at the
    // first import it calls, which names the next shim to write.
    @objc private func testCoreFP() {
        guard let path = Bundle.main.path(forResource: "corefp", ofType: "x64i",
                                          inDirectory: "assets") else {
            report += "\n[X64] corefp.x64i missing from the bundle"
            textView.text = report
            return
        }
        // Larger than the other probes: this report also lists which imports
        // were served and how often.
        var buffer = [CChar](repeating: 0, count: 16384)
        x64probe_report(path, 0, &buffer, buffer.count)
        report += "\n" + String(cString: buffer)
        textView.text = report
        UIPasteboard.general.string = report
    }

    // CommerceKit for OS X 10.9, called through _cp2g1b9ro with the real
    // argument shape. This is the first test that is about SAP rather than
    // about the emulator.
    @objc private func testSAP() {
        guard let path = Bundle.main.path(forResource: "commercekit", ofType: "x64i",
                                          inDirectory: "assets") else {
            report += "\n[X64] commercekit.x64i missing from the bundle"
            textView.text = report
            return
        }
        var buffer = [CChar](repeating: 0, count: 16384)
        x64probe_report(path, 1, &buffer, buffer.count)
        report += "\n" + String(cString: buffer)
        textView.text = report
        UIPasteboard.general.string = report
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
