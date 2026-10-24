import UIKit

@main
final class AppDelegate: UIResponder, UIApplicationDelegate {

    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions launchOptions:
                        [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        print("[DLiPA] AppDelegate.didFinishLaunchingWithOptions start")

        // Black-box recorder: redirect stderr to a file in Caches BEFORE
        // any SAP code runs. If the Go runtime later dies with
        // "fatal error: signal: SIGSEGV" inside Unicorn (cgo), the
        // message lands in dlipa-stderr.log. On the next launch we read
        // it back and dump it into AppLog so the user can Share-log it.
        // Without this, cgo-level signals kill the process silently and
        // we never see why.
        StderrCapture.start()

        // PLAN.md step 0, and the cheapest question in the whole project:
        // does iOS already ship the FairPlay / Store components we currently
        // extract from macOS? If it does, they are iOS binaries and dyld can
        // load them directly, which removes chained fixups, pointer
        // authentication, the macOS-only framework dependencies, and the need
        // to emulate anything. Runs first so its output is captured even if a
        // later step kills the process.
        FrameworkProbe.run()

        // Attempt to enable JIT by setting CS_DEBUGGED via ptrace.
        // This must happen before any Unicorn code runs.
        JITEnabler.enable()

        // Test whether iOS allows mmap(PROT_EXEC) on a signed bundle file.
        // This determines if the native execution approach (replacing Unicorn)
        // is viable on this device.
        ExecTest.testBundleFileExec()

        // Log the BuildID.txt that CI bakes into the bundle. This is the
        // single most useful line in the device log when chasing a
        // stale-IPA install: it identifies which CI build is *actually*
        // running on the device, not which CI build the user *thinks*
        // they installed. Without it, a TrollStore over-install that
        // kept the old bundle is indistinguishable from a fresh install.
        if let buildIDURL = Bundle.main.url(forResource: "BuildID", withExtension: "txt"),
           let buildID = try? String(contentsOf: buildIDURL, encoding: .utf8) {
            // Log each line as a separate INFO line so it shows up in
            // the device syslog filter the user is already using.
            // One big block would still be visible but per-line is
            // easier to grep.
            for line in buildID.split(separator: "\n") {
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                if !trimmed.isEmpty {
                    AppLog.info("BuildID: " + trimmed, .app)
                }
            }
        } else {
            AppLog.error("BuildID.txt not found in bundle — this is not a CI build", .app)
        }
        // Staging is back on the launch path.
        //
        // It was dropped when signing ran through sap_guest.c and the OS X 10.9
        // container: that engine read its own image and needed none of the four
        // macOS 27 binaries. Signing now goes through the Go bridge's arm64
        // machine, which reads those four from a directory it is told about, and
        // they ship inside the bundle. Copying them somewhere writable and
        // pointing the bridge at it is exactly what AssetStaging does.
        //
        // It runs in the background: the copy is ~125 MB, and the first sign-in
        // is the first thing that needs it.
        AssetStaging.stageIfNeeded(progress: nil) { error in
            if let error {
                AppLog.error("asset staging failed: " + error.localizedDescription, .assets)
            } else {
                AppLog.info("SAP assets staged for the arm64 bridge", .assets)
            }
        }
        print("[DLiPA] AppDelegate.didFinishLaunchingWithOptions returning true")
        return true
    }

    // MARK: UISceneSession Lifecycle

    func application(_ application: UIApplication,
                     configurationForConnecting connectingSceneSession: UISceneSession,
                     options: UIScene.ConnectionOptions) -> UISceneConfiguration {
        UISceneConfiguration(name: "Default Configuration", sessionRole: connectingSceneSession.role)
    }
}
