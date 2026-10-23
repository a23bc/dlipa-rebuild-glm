import SwiftUI

struct SettingsScreen: View {
    var body: some View {
        NavigationView {
            List {
                Section("Identity") {
                    LabeledContent("Device GUID", value: "generated at sign-in")
                }
                Section("SAP") {
                    LabeledContent("Version", value: "200 / 210")
                    LabeledContent("Backend", value: "Unicorn guest")
                }
                Section("About") {
                    LabeledContent("App", value: "DLiPA Rebuild")
                }
            }
            .navigationTitle("Settings")
        }
        .navigationViewStyle(.stack)
    }
}
