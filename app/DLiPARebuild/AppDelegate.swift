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
            } else {
                // Both branches, for the reason the shared-cache switch above
                // already gives: a one-sided log cannot tell a decision from a
                // block that never ran. A device run on 2026-11-06 needed exactly
                // that distinction -- no clear line appeared, and whether that
                // meant the key matched or the launch never reached here decides
                // whether the data container survived the install.
                AppLog.info("kbsync cache kept: version " + current + " unchanged", .sap)
            }

            // Read before anything can open the store runtime: open() decides once,
            // from this, whether the shared cache is mapped up front or handed out a
            // page at a time, and a decision made after the open would be a decision
            // about the next launch while reporting this one.
            // Both directions log, the way the pre-warm switch right below does.
            // A switch that is silent when off cannot be told apart from a switch
            // that was never read -- the first lazy measurement came back on the
            // eager path and the log could not say whether anyone had flipped it.
            //
            // On unless the diagnostics switch says otherwise. The switch used to
            // be the way to get the fast path; measured device-side, the demand
            // shape opens in 1.2 s against 99.3 s mapped in full, and the two
            // flows that were watched asked the cache for no pages at all, so
            // now it is the way back out.
            let lazyCachePages = UserDefaults.standard.object(forKey: DiagnosticsScreen.lazyCacheKey) as? Bool ?? true

            if lazyCachePages {
                SapbridgeEnableLazyCachePages()
                AppLog.info("shared cache: pages will be mapped on demand", .sap)
            } else {
                AppLog.info("shared cache: mapped in full at open (switch off)", .sap)
            }

            // On unless the diagnostics row says otherwise, the way the shared
            // cache row above works: measured on device, three accounts in one
            // launch served three downloads through the runtime the first of them
            // opened. Logged in both directions for the reason the switch above
            // gives -- a refusal and an unread preference look the same when only
            // one branch prints.
            let accountReuse = UserDefaults.standard.object(forKey: DiagnosticsScreen.accountReuseKey) as? Bool ?? true

            if accountReuse {
                SapbridgeEnableAccountReuseProbe()
                AppLog.info("account switch: a second account reuses the runtime (probe)", .sap)
            } else {
                AppLog.info("account switch: a second account is refused until a restart", .sap)
            }

            // Off unless the diagnostics row asks, the way the pre-warm row below
            // works. The census lines this turns on are the loudest part of an
            // open -- 89 of the 118 lines that second holds, against 38 with this
            // switch off -- and they answer questions about the mapping, not about
            // the download, in the log a bug report gets typed into. Both directions
            // still print: a launch that logged no census has to be able to say
            // whether that was the switch or the open that never happened.
            let mappingCensus = UserDefaults.standard.bool(forKey: DiagnosticsScreen.mappingCensusKey)

            if mappingCensus {
                SapbridgeEnableMappingCensus()
                AppLog.info("map census: mapping measurements will be logged", .sap)
            } else {
                AppLog.info("map census: off by switch, the mapping measurements are not logged", .sap)
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

        // Probe build only, and the whole reason this branch exists: whether the
        // data-protection keychain accepts an item on a build signed the way this
        // app is signed, and whether that item outlives the launch that wrote it.
        // The answers decide where the session tokens, the cookie jar, the device
        // identity and the kbsync blob go, so they get measured here instead of
        // being assumed by the migration that would move them. What the two lines
        // mean, and what each possible answer rules in or out, is written up in
        // docs/probes/keychain-shapes.md.
        KeychainProbe.run()

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
