import SwiftUI

/// Deployment target is 15.0, so no LabeledContent: it needs 16.
private struct Row: View {
    let title: String
    let value: String

    var body: some View {
        HStack {
            Text(title)
            Spacer()
            Text(value).foregroundColor(.secondary)
        }
    }
}

struct SettingsScreen: View {
    var body: some View {
        NavigationView {
            List {
                Section("Identity") {
                    Row(title: "Device GUID", value: "generated at sign-in")
                }
                Section("SAP") {
                    Row(title: "Version", value: "200 / 210")
                    Row(title: "Backend", value: "Unicorn guest")
                }
                Section("About") {
                    Row(title: "App", value: "DLiPA Rebuild")
                }
            }
            .navigationTitle("Settings")
        }
        .navigationViewStyle(.stack)
    }
}
