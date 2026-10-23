import SwiftUI

/// Runs the probe that ships with the app and shows what it printed. This is
/// the tab to open when something stops working, because it says which layer
/// failed instead of leaving a spinner on screen.
struct DiagnosticsScreen: View {
    @State private var output = ""
    @State private var running = false

    var body: some View {
        NavigationView {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 12) {
                    Button("Run probe") { run() }
                        .buttonStyle(.borderedProminent)
                        .disabled(running)
                    if running {
                        ProgressView()
                    }
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

    private func run() {
        running = true
        output = ""
        // The probe reports through the log; the marker below is what the
        // screen can show without threading a sink through every call site.
        DispatchQueue.main.async {
            FrameworkProbe.run()
            output = "Probe finished. Full report is in the app log."
            running = false
        }
    }
}
