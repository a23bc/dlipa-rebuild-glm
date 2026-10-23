import SwiftUI

/// Deployment target is 15.0, so no LabeledContent: it needs 16.
private struct Row: View {
    let title: String
    let value: String
    var caption: String? = nil

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(alignment: .firstTextBaseline) {
                Text(title)
                Spacer()
                Text(value)
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.trailing)
            }
            if let caption {
                Text(caption)
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
        }
        .padding(.vertical, 2)
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
                Section {
                    Row(title: "Device GUID",
                        value: guid,
                        caption: "The identity Apple sees. It is sent with every signed request and must match the SAP signing session exactly.")
                    Button(role: .destructive) {
                        confirmingReset = true
                    } label: {
                        Text("Regenerate device GUID")
                    }
                } header: {
                    Text("Identity")
                } footer: {
                    Text("A new GUID signs you out, discards the cached download keys, and makes Apple treat this as a different device. Only do it if the current identity is unusable.")
                }

                Section("SAP") {
                    Row(title: "Protocol", value: "200 / 210",
                        caption: "Certificate leg and reply leg versions")
                    Row(title: "Backend", value: "Unicorn guest",
                        caption: "CommerceKit 10.9 under an x86 interpreter")
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
                    message: Text("This signs you out, discards cached download keys, and makes Apple treat this as a new device. The old identity cannot be recovered."),
                    primaryButton: .destructive(Text("Regenerate")) { regenerate() },
                    secondaryButton: .cancel())
            }
        }
        .navigationViewStyle(.stack)
    }

    private func regenerate() {
        // Order matters: the cached kbsync blobs belong to the identity that is
        // about to be replaced, so they go first.
        SAPSigner.forgetAllCachedKBSync()
        guid = HardwareIdentity.regenerate().guid
        // regenerate() posts the change notification; AccountsScreen listens for
        // it and tears down its live session.
    }
}
