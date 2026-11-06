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
    /// shared cache up front -- the census prices that at about 0.8 s per MiB, which
    /// is the 32.8 s the launch pays -- or index the pages and hand one over when the
    /// guest touches it, about 4 ms per page and nothing at all for the rest.

    /// It takes effect at the next launch rather than at the tap, because open()
    /// reads the choice once. Off is the shape every build has shipped with.
    static let lazyCacheKey = "com.a23bc.dliparebuild.lazyCachePages"
    @AppStorage(lazyCacheKey) private var lazyCachePages = false
    @State private var logText = ""

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
                    Text(logText.isEmpty ? "No log entries yet." : logText)
                        .font(.system(.caption2, design: .monospaced))
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.horizontal, 12)
                        .padding(.vertical, 8)
                        .textSelection(.enabled)
                }
            }
            .navigationTitle("Diagnostics")
            .onAppear {
                AppLog.onUpdate { _ in refresh() }
                refresh()
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
        // The tail, not everything. The view lays out this string on the main
        // thread, and the probe can add a thousand lines in one run: rendering
        // all of them on every refresh is main-thread work that competes with
        // the very thing it is reporting on. The full log is still exported by
        // the share button.
        let text = AppLog.exportText()
        let lines = text.split(separator: "\n", omittingEmptySubsequences: false)

        if lines.count > 400 {
            logText = "… " + String(lines.count - 400) + " earlier lines omitted …\n"
                + lines.suffix(400).joined(separator: "\n")
        } else {
            logText = text
        }
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
