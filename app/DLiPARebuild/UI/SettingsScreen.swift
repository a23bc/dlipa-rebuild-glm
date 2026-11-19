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
    /// Set once the Diagnostics tab has been unlocked. Shared with RootTabView.
    static let showDiagnosticsKey = "com.a23bc.dliparebuild.showDiagnostics"
    /// Search result limit: 25 / 50 / 100, or -1 for the custom value below.
    static let resultLimitKey = "com.a23bc.dliparebuild.searchResultLimit"
    static let customLimitKey = "com.a23bc.dliparebuild.searchCustomLimit"

    /// Taps needed on the About row before the Diagnostics tab appears.
    private static let unlockTaps = 5

    static var appVersion: String {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "unknown"
    }

    @AppStorage(showDiagnosticsKey) private var showDiagnostics = false
    @AppStorage(resultLimitKey) private var resultLimit = 50
    @AppStorage(customLimitKey) private var customLimit = 50

    /// Read on appear and again after a regeneration: the value lives in
    /// UserDefaults, not in observable state.
    @State private var guid = HardwareIdentity.current().guid
    @State private var confirmingReset = false
    @State private var confirmingWipe = false
    @State private var unlockTapsSoFar = 0
    @State private var lastTap = Date.distantPast

    var body: some View {
        NavigationView {
            List {
                // Search sits above Identity: the result limit is the setting
                // people reach for most often.
                Section("Search") {
                    NavigationLink {
                        ResultLimitView(limit: $resultLimit, custom: $customLimit)
                    } label: {
                        Row(title: "Result limit", value: resultLimit < 0 ? "Custom (\(customLimit))" : "\(resultLimit)")
                    }
                }

                Section("Identity") {
                    Row(title: "Device GUID", value: guid)
                    Button(role: .destructive) {
                        confirmingReset = true
                    } label: {
                        Text("Regenerate device GUID")
                    }
                }

                if showDiagnostics {
                    Section {
                        Toggle("Show Diagnostics tab", isOn: $showDiagnostics)
                    }
                }

                // The wipe sits immediately above About, so the destructive
                // action is near the identity it destroys rather than buried.
                Section {
                    Button(role: .destructive) {
                        confirmingWipe = true
                    } label: {
                        Text("Reset all data")
                    }
                }

                // About is last. A tap on Version unlocks the Diagnostics tab.
                Section("About") {
                    NavigationLink {
                        AboutRepositoryView()
                    } label: {
                        Text("Github Repository")
                    }
                    Button {
                        registerUnlockTap()
                    } label: {
                        Row(title: "Version", value: Self.appVersion)
                    }
                    .buttonStyle(.plain)
                }
            }
            .navigationTitle("Settings")
            .onAppear {
                guid = HardwareIdentity.current().guid
            }
            .alert(isPresented: $confirmingReset) {
                Alert(
                    title: Text("Regenerate device GUID?"),
                    message: Text("Signs you out, discards cached download keys, and makes Apple treat this as a new device."),
                    primaryButton: .destructive(Text("Regenerate")) { regenerate() },
                    secondaryButton: .cancel())
            }
            .alert(isPresented: $confirmingWipe) {
                Alert(
                    title: Text("Reset all data?"),
                    message: Text("Removes every account and password, the machine identity, cached download keys and all app settings. This cannot be undone."),
                    primaryButton: .destructive(Text("Reset")) { wipeAll() },
                    secondaryButton: .cancel())
            }
        }
        .navigationViewStyle(.stack)
    }

    /// Counts taps on the About row. A gap longer than a second starts over, so
    /// stray taps over a session never add up to an unlock.
    private func registerUnlockTap() {
        guard !showDiagnostics else { return }
        let now = Date()
        if now.timeIntervalSince(lastTap) > 1.0 {
            unlockTapsSoFar = 0
        }
        lastTap = now
        unlockTapsSoFar += 1
        if unlockTapsSoFar >= Self.unlockTaps {
            unlockTapsSoFar = 0
            showDiagnostics = true
            AppLog.info("diagnostics tab unlocked", .app)
        }
    }

    private func regenerate() {
        SAPSigner.forgetAllCachedKBSync()
        guid = HardwareIdentity.regenerate().guid
    }

    /// Clears everything the app owns: accounts and tokens (UserDefaults), stored
    /// passwords and the anisette state (Keychain), cached kbsync blobs and the
    /// search history. The process is told to leave so no in-memory state survives.
    private func wipeAll() {
        let defaults = UserDefaults.standard
        for key in defaults.dictionaryRepresentation().keys where key.hasPrefix("com.a23bc.dliparebuild") {
            defaults.removeObject(forKey: key)
        }
        Keychain.removeAll()
        SAPSigner.forgetAllCachedKBSync()
        AppLog.clear()
        AppLog.info("all app data reset", .app)

        DispatchQueue.main.asyncAfter(deadline: .now() + 0.2) {
            exit(0)
        }
    }
}

/// The second-level page for the result limit. Custom is edited here, so the
/// main settings list never grows a stepper that pushes rows around.
private struct ResultLimitView: View {
    @Binding var limit: Int
    @Binding var custom: Int

    var body: some View {
        Form {
            Section {
                Picker("Preset", selection: $limit) {
                    Text("25").tag(25)
                    Text("50").tag(50)
                    Text("100").tag(100)
                    Text("Custom").tag(-1)
                }
                .pickerStyle(.inline)
            }
            if limit < 0 {
                Section("Custom limit") {
                    Stepper(value: $custom, in: 1...1000, step: 5) {
                        Text("\(custom) results")
                    }
                }
            }
        }
        .navigationTitle("Result limit")
    }
}

/// Destination for the About link. Keeping it a real navigation link gives the
/// chevron style without a blue text label.
private struct AboutRepositoryView: View {
    private static let url = "https://github.com/a23bc/dlipa-rebuild-glm"

    var body: some View {
        Form {
            Section {
                Link("Open in Safari", destination: URL(string: Self.url)!)
            }
            Section {
                Text(Self.url)
                    .font(.footnote)
                    .foregroundColor(.secondary)
                    .textSelection(.enabled)
            }
        }
        .navigationTitle("Github Repository")
    }
}
