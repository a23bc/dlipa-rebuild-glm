import SwiftUI

/// Runs the probes that ship with the app and shows what they printed. This
/// is the tab to open when something stops working, because it says which
/// layer failed instead of leaving a spinner on screen.
struct DiagnosticsScreen: View {
    @State private var output = ""
    @State private var running = false

    var body: some View {
        NavigationView {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 12) {
                    Button("Run SAP self test") { runSAP() }
                        .buttonStyle(.borderedProminent)
                        .disabled(running)
                    if running { ProgressView() }
                }
                .padding(.horizontal)

                HStack(spacing: 12) {
                    Button("Run framework probe") { runFrameworkProbe() }
                        .disabled(running)
                    Button("Share log") { shareLog() }
                        .disabled(running)
                }
                .padding(.horizontal)

                ScrollView {
                    Text(output.isEmpty ? "No output yet." : output)
                        .font(.system(.caption, design: .monospaced))
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.horizontal)
                        .textSelection(.enabled)
                }
            }
            .navigationTitle("Diagnostics")
        }
        .navigationViewStyle(.stack)
    }

    /// The question this answers: does the probeapp chain run on this device.
    /// Nothing here touches the account UI, so it works before sign-in is
    /// wired up - which is the point, since a sign-in failure would otherwise
    /// be indistinguishable from a broken emulator.
    private func runSAP() {
        running = true
        output = ""
        SAPSelfTest.run { line in
            output += line + "\n"
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
        output = ""
        DispatchQueue.main.async {
            FrameworkProbe.run()
            output = "Framework probe finished. Full report is in the app log.\n"
            running = false
        }
    }

    private func shareLog() {
        let text = AppLog.exportText()
        guard !text.isEmpty else {
            output = "The log is empty."
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
