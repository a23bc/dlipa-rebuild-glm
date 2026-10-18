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
        // The four Apple SAP binaries are about 119 MB. Copying them on the
        // main thread would stall launch, so staging runs in the background
        // and signing is blocked until it finishes.
        AssetStaging.stageIfNeeded { error in
            if let error {
                AppLog.error("staging failed: " + String(describing: error), .assets)
                print("[DLiPA] AppDelegate: staging failed: \(error)")
            } else {
                print("[DLiPA] AppDelegate: staging completed")
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
