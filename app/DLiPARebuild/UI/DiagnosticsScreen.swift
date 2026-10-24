import SwiftUI
import UIKit

/// The tab that answers "what actually happened".
///
/// The probes report into the same log as everything else, and the log is shown
/// here rather than only in Console.app, because attaching a device to a
/// debugger is not something anyone wants to do to report a bug.
struct DiagnosticsScreen: View {
    @State private var running = false
    @State private var recording = AppLog.isRecording
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
                    }

                    Section {
                        Button("Run SAP self test") { runSAP() }
                            .disabled(running)
                        Button("Run framework probe") { runFrameworkProbe() }
                            .disabled(running)
                        Button("Generate kbsync (Gate 0)") { runKBSync() }
                            .disabled(running)
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

    private func refresh() {
        logText = AppLog.exportText()
    }

    /// The question this answers: does the probeapp chain run on this device.
    /// Nothing here touches the account UI, so it works before sign-in.
    private func runSAP() {
        running = true
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
        Task {
            _ = await AppSession.shared.diagnosticKBSync()
            running = false
        }
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
