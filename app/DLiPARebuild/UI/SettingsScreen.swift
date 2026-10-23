import SwiftUI

/// Deployment target is 15.0, so no LabeledContent: it needs 16.
private struct Row: View {
    let title: String
    let value: String

    var body: some View {
        HStack(alignment: .firstTextBaseline) {
            Text(title)
            Spacer()
            Text(value)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.trailing)
        }
    }
}

struct SettingsScreen: View {
    /// Read on appear and again after a regeneration: the value lives in
    /// UserDefaults, not in observable state.
    @State private var guid = HardwareIdentity.current().guid
    @State private var confirmingReset = false

    var body: some View {
        NavigationView {
            List {
                Section("Identity") {
                    Row(title: "Device GUID", value: guid)
                    Button(role: .destructive) {
                        confirmingReset = true
                    } label: {
                        Text("Regenerate device GUID")
                    }
                }

                Section("SAP") {
                    Row(title: "Protocol", value: "200 / 210")
                    Row(title: "Backend", value: "Unicorn guest")
                }

                Section("About") {
                    Row(title: "App", value: "DLiPA Rebuild")
                    Row(title: "Bundle", value: "com.a23bc.dliparebuild")
                }
            }
            .navigationTitle("Settings")
            .onAppear {
                // The tab may be shown long after a regeneration happened.
                guid = HardwareIdentity.current().guid
            }
            .alert(isPresented: $confirmingReset) {
                Alert(
                    title: Text("Regenerate device GUID?"),
                    message: Text("Signs you out, discards cached download keys, and makes Apple treat this as a new device."),
                    primaryButton: .destructive(Text("Regenerate")) { regenerate() },
                    secondaryButton: .cancel())
            }
        }
        .navigationViewStyle(.stack)
    }

    private func regenerate() {
        // The cached kbsync blobs belong to the identity being replaced.
        SAPSigner.forgetAllCachedKBSync()
        guid = HardwareIdentity.regenerate().guid
        // regenerate() posts the change notification; AccountsScreen listens
        // for it and tears down its live session.
    }
}
