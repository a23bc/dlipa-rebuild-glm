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

        // The framework probe answers PLAN.md step 0: does iOS already ship the
        // FairPlay / Store components we extract from macOS? It ran on every
        // launch until now, which cost ~30 lines of noise at the top of every
        // log and buried whatever had actually just happened. It is a question
        // that gets asked once, so it is now a button on the Diagnostics screen.
        // Its answer is still captured there if a later step kills the process,
        // because StderrCapture is already running by the time it is pressed.

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
                return
            }

            // Two different successes share this callback: the binaries were
            // copied out of the bundle, or this build ships none and the bridge
            // will fetch them. Saying "staged" for the second one is a lie that
            // costs an hour when someone reads the log to find out why sign-in
            // is slow.
            AppLog.info(AssetStaging.resolvesOnDemand
                ? "SAP assets are not bundled; the first sign-in resolves them from Apple"
                : "SAP assets staged for the arm64 bridge", .assets)

            // Pre-warming at launch is off.
            //
            // It was here to keep the 2 minutes of emulated startup off the
            // first tap, but the engine's own initialisation is what crashes at
            // launch: uc_open succeeds, then the deferred UC_INIT on the first
            // mem_map fails to allocate its translator buffer and QEMU calls
            // exit(1). No exception, no crash report. Doing it at launch meant
            // every launch could die before the user saw anything.
            //
            // Opening on first use moves that risk to the one action that needs
            // the store, where a failure at least follows something the user
            // asked for.
            // A switch, not a policy. Opening the engine at launch is the one
            // step that can end the process before a screen is drawn; not opening
            // it costs two minutes on the first thing that needs the store.
            // A new version starts from no cached session material. The kbsync
            // blobs carry the assumptions of the binary that wrote them, and
            // after an upgrade the old one makes the guest reject the request in
            // setup -- which looked like a broken account until a clean install
            // worked.
            //
            // The version, not the CI build number. The build number changes on
            // every push, and clearing on it cost the first download of each new
            // build a kbsync regeneration: 117 s with nothing in the log between
            // the request and the open, then 0 s on the next launch, which read
            // the blob back off disk. A key that is too coarse still self-heals
            // -- Apple's rejection drops the stored blob, so the worst case is
            // one failed download rather than a dead account.
            let versionKey = "com.a23bc.dliparebuild.lastVersion"
            let current = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0"

            if UserDefaults.standard.string(forKey: versionKey) != current {
                var failure: NSError?
                _ = SapbridgeClearCachedKBSync(&failure)

                if let failure {
                    AppLog.warn("kbsync cache clear failed: " + failure.localizedDescription, .sap)
                } else {
                    AppLog.info("new version " + current + ": kbsync cache cleared", .sap)
                }

                UserDefaults.standard.set(current, forKey: versionKey)
            }

        // Read before anything can open the store runtime: open() decides once,
        // from this, whether the shared cache is mapped up front or handed out a
        // page at a time, and a decision made after the open would be a decision
        // about the next launch while reporting this one.
        // Both directions log, the way the pre-warm switch right below does.
        // A switch that is silent when off cannot be told apart from a switch
        // that was never read -- the first lazy measurement came back on the
        // eager path and the log could not say whether anyone had flipped it.
        if UserDefaults.standard.bool(forKey: DiagnosticsScreen.lazyCacheKey) {
            SapbridgeEnableLazyCachePages()
            AppLog.info("shared cache: pages will be mapped on demand", .sap)
        } else {
            AppLog.info("shared cache: mapped in full at open (switch off)", .sap)
        }

        // Off unless asked for. Opening the engine at launch is the step that
            // can end the process before a screen is drawn, and it is now a
            // diagnostic switch rather than a default.
            let prewarm = UserDefaults.standard.bool(forKey: DiagnosticsScreen.prewarmKey)

            if prewarm {
                Task { @MainActor in
                    await AppSession.shared.prewarmSAPRuntime()
                }
            } else {
                AppLog.info("SAP pre-warm off by switch: the engine opens on first use", .sap)
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
