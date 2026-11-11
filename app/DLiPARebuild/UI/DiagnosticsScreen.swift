import SwiftUI
import UIKit

/// The tab that answers "what actually happened".
///
/// The probes report into the same log as everything else, and the log is shown
/// here rather than only in Console.app, because attaching a device to a
/// debugger is not something anyone wants to do to report a bug.
struct DiagnosticsScreen: View {
    @State private var running = false
    /// When the current probe started. The Store runtime takes long enough that
    /// a disabled button with no other change reads as a hang, so the elapsed
    /// time is shown instead.
    @State private var started = Date()
    /// A main-queue heartbeat while a probe runs.
    ///
    /// The store probe leaves the main thread free by design, yet the app becomes
    /// unusable during it while the spinner keeps animating -- which says the
    /// main thread is blocked, not that the work is merely slow. These lines make
    /// that visible: if they stop while the spinner still turns, main is blocked
    /// and the last one printed marks when.
    @State private var heartbeat: Timer?
    /// Whether the SAP runtime opens at launch.
    ///
    /// Off by default: the open is the step that can end the process before a
    /// screen is drawn. On, it makes the first download reuse a session that is
    /// already built.
    static let prewarmKey = "com.a23bc.dliparebuild.prewarmAtLaunch"
    @State private var recording = AppLog.isRecording
    @AppStorage(prewarmKey) private var prewarmAtLaunch = false

    /// Which shape the next store-runtime open takes: map all 38.8 MiB of the
    /// shared cache up front, or index the pages and hand one over only when the
    /// guest touches it.
    ///
    /// Device, both shapes: 99.3 s to open mapped in full, 1.2 s indexed, and of
    /// that 1.2 s the indexing itself is 336 ms. The two flows watched afterwards
    /// asked the cache for no page at all, which is what the second shape bets on.
    ///
    /// It takes effect at the next launch rather than at the tap, because open()
    /// reads the choice once. On is the default; off is kept as the way back to
    /// the shape every earlier build shipped with, and to measure against it.
    static let lazyCacheKey = "com.a23bc.dliparebuild.lazyCachePages"
    @AppStorage(lazyCacheKey) private var lazyCachePages = true

    /// Whether a download for a second account may run through the store runtime
    /// the first account opened, instead of being refused with "restart the app".
    ///
    /// On by default, since device: one launch, A then B then A again, three
    /// downloads served, each with its own kbsync resolved by dsid. Nothing about
    /// the account lives in the runtime -- the request carries the blob, the
    /// account object and the headers -- and off is kept as the way back to the
    /// refusal for comparison.
    ///
    /// Nothing is closed to make this happen. Closing is measured broken: the
    /// next signature after a close returned -42306 with and without releasing
    /// the address space, so a design that avoids the close is worth more here.
    ///
    /// Applied at launch, like the other two rows: the bridge reads the flag on
    /// every download, but nothing enables it until the next launch, so flipping
    /// this row changes the run after it and not the one in hand. The log says
    /// which shape a launch took -- `account switch: a second account reuses the
    /// runtime (probe)` or `... is refused until a restart` -- and a download that
    /// switches prints `reusing DSID <a>'s store runtime for DSID <b>`.
    static let accountReuseKey = "com.a23bc.dliparebuild.accountReuseProbe"
    @AppStorage(accountReuseKey) private var accountReuse = true

    /// Whether the next store-runtime open prints the mapping measurements: one
    /// line per used cell of the map-cost census, and one per region mapped page
    /// by page.
    ///
    /// Off by default. They are the loudest thing in a normal launch -- 89 of the
    /// 118 lines an open writes inside its own second, against 38 in that second
    /// with this row off, both counted on device at the build that added it -- and
    /// they are about the mapping rather than about the download, in the same log a
    /// bug report gets typed into.
    ///
    /// It takes effect at the next launch, because open() reads it once. On is what
    /// every build up to this switch printed, and it stays switchable because the
    /// census is what killed three speculative levers and found the coupling
    /// between the region phase and the shared cache.
    ///
    /// The log says which shape a launch took -- `map census: mapping measurements
    /// will be logged` or `map census: off by switch, ...` -- and what the lines
    /// mean, with the numbers they produced, is in `docs/diagnostics.md`.
    static let mappingCensusKey = "com.a23bc.dliparebuild.mappingCensus"
    @AppStorage(mappingCensusKey) private var mappingCensus = false

    /// Routes sign-in through the Store runtime instead of the hand-built
    /// request. Off by default: it is the comparison arm, not the shipping
    /// path, until a device run says otherwise.
    @AppStorage(AppStoreClient.nativeAuthenticateKey) private var nativeAuthenticate = false
    // The tail as entries rather than as one joined string: the rows are laid
    // out lazily now, so the cost is what fits on screen, not what fits in the
    // window.
    @State private var tail: [LogEntry] = []
    @State private var omitted = 0
    @State private var lastRender = Date.distantPast
    @State private var renderQueued = false

    var body: some View {
        NavigationView {
            VStack(spacing: 0) {
                Form {
                    Section {
                        Toggle("Record log", isOn: $recording)
                            .onChange(of: recording) { value in
                                // Release builds drop .debug before anyone can
                                // read it; this is the switch that keeps it.
                                AppLog.isRecording = value
                                refresh()
                            }
                        Toggle("Open the SAP runtime at launch", isOn: $prewarmAtLaunch)
                            .onChange(of: prewarmAtLaunch) { _ in refresh() }
                        Toggle("Map the shared cache on demand (next launch)", isOn: $lazyCachePages)
                            .onChange(of: lazyCachePages) { _ in refresh() }
                        Toggle("Reuse one runtime across accounts (next launch)",
                               isOn: $accountReuse)
                            .onChange(of: accountReuse) { _ in refresh() }
                        Toggle("Log the mapping measurements (next launch)",
                               isOn: $mappingCensus)
                            .onChange(of: mappingCensus) { _ in refresh() }
                        Toggle("Authenticate through the Store runtime",
                               isOn: $nativeAuthenticate)
                            .onChange(of: nativeAuthenticate) { _ in refresh() }
                    }

                    Section {
                        Button("Run SAP self test") { runSAP() }
                            .disabled(running)
                        Button("Run framework probe") { runFrameworkProbe() }
                            .disabled(running)
                        Button("Generate kbsync (Gate 0)") { runKBSync() }
                            .disabled(running)
                        Button("Open Store runtime (E1-a)") { runStoreSmoke() }
                            .disabled(running)

                        // Measurement, not a feature: the same extraction CI runs, on
                        // this device. It asks go-macho for about 1.6 GB in one
                        // allocation during the export step, which is enough to end the
                        // process -- worth knowing before it is called harmless.
                        Button("Fetch SAP assets (measure)") { fetchAssets() }
                            .disabled(running)
                    }

                    if running {
                        Section {
                            // The guest can run for minutes. Without this the
                            // screen only shows greyed-out buttons, which is
                            // indistinguishable from a freeze.
                            TimelineView(.periodic(from: started, by: 1)) { context in
                                HStack(spacing: 8) {
                                    ProgressView()
                                    Text("working… \(Int(context.date.timeIntervalSince(started)))s")
                                        .foregroundColor(.secondary)
                                }
                            }
                        }
                    }

                    Section {
                        Button("Share log") { shareLog() }
                        Button("Clear log", role: .destructive) {
                            AppLog.clear()
                            refresh()
                        }
                    }
                }
                .frame(height: 300)

                Divider()

                ScrollView {
                    // Rows, and lazy ones. A single Text holding four hundred
                    // joined lines made the screen build one text layout and one
                    // selection grammar over roughly a hundred kilobytes --
                    // seconds on entry, before anything else had run. A LazyVStack
                    // gives the layout to the rows that are visible, so entering
                    // the screen stops costing what the window holds.
                    LazyVStack(alignment: .leading, spacing: 2) {
                        if omitted > 0 {
                            Text("… " + String(omitted) + " earlier entries omitted …")
                                .font(.system(.caption2, design: .monospaced))
                                .foregroundColor(.secondary)
                        }

                        ForEach(tail) { entry in
                            Text(entry.plainText)
                                .font(.system(.caption2, design: .monospaced))
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .textSelection(.enabled)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 8)
                }
            }
            .navigationTitle("Diagnostics")
            .onAppear {
                AppLog.onChanged { refresh() }
                refresh()
            }
            .onDisappear {
                // Released, not left armed. The handler sat in a static slot, so
                // every line written after this screen was opened once re-rendered
                // its text for the rest of the session -- which is how a guest run
                // froze a screen the user had already left, for exactly as long as
                // the run that produced the lines took.
                AppLog.onChanged(nil)
            }
        }
        .navigationViewStyle(.stack)
    }

    /// Uses the screen's own running state and clock, like the other probes: a
    /// second progress mechanism on the same screen is a second thing to go wrong.
    ///
    /// Through AssetStaging rather than straight at the bridge, so that pressing
    /// this while a download is already waiting on the same fetch joins that run
    /// instead of starting a second 212 MB download of the same restore image.
    private func fetchAssets() {
        running = true
        started = Date()

        AssetStaging.resolveFromApple { report, error in
            if let error {
                // The cost rides inside the error too, so this line is the whole answer.
                AppLog.error("fetch assets failed: " + error.localizedDescription, .sap)
            } else {
                AppLog.info("fetch assets finished: " + (report ?? "no report"), .sap)
            }

            Task { @MainActor in running = false }
        }
    }

    private func refresh() {
        // At most one render per quarter second. AppLog already coalesces its
        // notifications to one per turn of the main thread, which bounds the
        // copies but not the layout: during a store-runtime open a turn is
        // sixteen milliseconds, so the tail would be rebuilt sixty times a
        // second -- and rebuilding it is exactly the main-thread work this
        // screen asks for while the guest is running on the other core.
        // Suppressed renders are folded into one follow-up rather than dropped,
        // so the window still ends up on screen once the burst stops.
        if Date().timeIntervalSince(lastRender) < 0.25 {
            if !renderQueued {
                renderQueued = true

                DispatchQueue.main.asyncAfter(deadline: .now() + 0.25) {
                    renderQueued = false
                    refresh()
                }
            }

            return
        }

        lastRender = Date()

        // The tail, read as a tail. It said so before while exporting the whole
        // window -- a synchronous copy of every entry, a formatted string for
        // each, one join, one split, and only then the last 400 lines joined
        // again. Reading 400 entries and laying out the twenty that are visible
        // is the same information; the share button still exports everything,
        // once, because that is a click.
        let fetched = AppLog.tail(400)

        tail = fetched
        omitted = AppLog.lineCount - fetched.count
    }

    /// The question this answers: does the probeapp chain run on this device.
    /// Nothing here touches the account UI, so it works before sign-in.
    private func runSAP() {
        running = true
        started = Date()
        SAPSelfTest.run { line in
            AppLog.info(line, .sap)
            if line.hasPrefix("SELF TEST PASSED") || line.hasPrefix("FAILED") {
                running = false
            }
        }
        // The chain is synchronous once started; release the buttons when it
        // settles even if a report line never arrives.
        DispatchQueue.main.asyncAfter(deadline: .now() + 120) {
            if running { running = false }
        }
    }

    private func runFrameworkProbe() {
        running = true
        started = Date()
        DispatchQueue.main.async {
            FrameworkProbe.run()
            AppLog.info("framework probe finished", .app)
            running = false
        }
    }

    /// Gate 0: can this device produce a kbsync blob at all. The answer decides
    /// whether the download plan continues.
    private func runKBSync() {
        running = true
        started = Date()
        Task {
            _ = await AppSession.shared.diagnosticKBSync()
            running = false
        }
    }

    private func runStoreSmoke() {

        running = true
        started = Date()

        beginHeartbeat()

        Task {
            let tick = Date()

            _ = await AppSession.shared.diagnosticStoreSmoke()

            stopHeartbeat()
            AppLog.info("store probe returned after "
                        + String(Int(Date().timeIntervalSince(tick))) + "s", .app)

            running = false

        }

    }

    /// Logs every two seconds from the main queue.
    private func beginHeartbeat() {
        stopHeartbeat()
        heartbeat = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { _ in
            AppLog.info("main alive at t+"
                        + String(Int(Date().timeIntervalSince(started))) + "s", .app)
        }
    }

    private func stopHeartbeat() {
        heartbeat?.invalidate()
        heartbeat = nil
    }

    

    private func shareLog() {
        let text = AppLog.exportText()
        guard !text.isEmpty else {
            AppLog.warn("share log pressed with an empty log", .app)
            return
        }
        let controller = UIActivityViewController(activityItems: [text],
                                                  applicationActivities: nil)
        if let scene = UIApplication.shared.connectedScenes.first as? UIWindowScene,
           let root = scene.keyWindow?.rootViewController {
            controller.popoverPresentationController?.sourceView = root.view
            root.present(controller, animated: true)
        }
    }
}
