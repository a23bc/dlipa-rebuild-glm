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

    /// Whether the SAP runtime opens at launch.
    ///
    /// On by default, because it is what makes the download work.
    ///
    /// Verified on device: with the engine opened at launch, the download reuses
    /// that session and succeeds; opening it later, after staging, fails. The open
    /// is not cheaper at launch, it is merely early enough that the process is
    /// still small. The remaining problem is that the open itself can fail at
    /// launch, and that is what is being worked on.
    static let prewarmKey = "com.a23bc.dliparebuild.prewarmAtLaunch"

    /// Whether a finished download is rewritten into a patched copy.
    ///
    /// Off by default: the patch is still being validated, and a package that has
    /// been rewritten is not the one Apple served. The original is never replaced,
    /// so switching this off is always safe.
    static let patchDownloadsKey = "com.a23bc.dliparebuild.patchDownloads"

    /// Taps needed on the About row before the Diagnostics tab appears.
    private static let unlockTaps = 5

    @AppStorage(showDiagnosticsKey) private var showDiagnostics = false
    @AppStorage(prewarmKey) private var prewarmAtLaunch = true
    @AppStorage(patchDownloadsKey) private var patchDownloads = false

    /// Read on appear and again after a regeneration: the value lives in
    /// UserDefaults, not in observable state.
    @State private var guid = HardwareIdentity.current().guid
    @State private var confirmingReset = false
    @State private var unlockTapsSoFar = 0
    @State private var lastTap = Date.distantPast

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
                    Button {
                        registerUnlockTap()
                    } label: {
                        Row(title: "App", value: "DLiPA Rebuild")
                    }
                    .buttonStyle(.plain)
                    Row(title: "Bundle", value: "com.a23bc.dliparebuild")
                }

                if showDiagnostics {
                    Section {
                        Toggle("Open the SAP runtime at launch", isOn: $prewarmAtLaunch)
                        Toggle("Patch downloads (rewrite iTunesMetadata)", isOn: $patchDownloads)
                        Toggle("Show Diagnostics tab", isOn: $showDiagnostics)
                    }
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
        // The cached kbsync blobs belong to the identity being replaced.
        SAPSigner.forgetAllCachedKBSync()
        guid = HardwareIdentity.regenerate().guid
        // regenerate() posts the change notification; AccountsScreen listens
        // for it and tears down its live session.
    }
}
