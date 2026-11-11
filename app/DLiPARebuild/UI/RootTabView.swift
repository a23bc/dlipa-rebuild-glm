import SwiftUI

/// The app shell. Structure follows the dlipa-next attempt: one tab per job,
/// each with its own navigation stack, and an empty state that says what the
/// screen will show rather than a blank page.
struct RootTabView: View {
    /// Diagnostics is hidden until it is unlocked from Settings. SwiftUI gives
    /// no callback for tapping the tab bar itself, so the unlock lives on a
    /// row inside Settings instead of on the tab, which cannot be intercepted
    /// without replacing the whole tab bar.
    @AppStorage(SettingsScreen.showDiagnosticsKey) private var showDiagnostics = false
    @ObservedObject private var downloads = DownloadManager.shared

    /// Which tab is showing. Held here so the fade can key off it: an
    /// `onAppear`-based one only ran the first time a tab was created, which is
    /// why the effect disappeared after switching back.
    @State private var selection = 0

    /// The one question this shell asks, and the two things it can report back.
    ///
    /// Held as one value because a view presents one alert: SearchScreen learned
    /// that the hard way, and two `.alert` modifiers here would leave one dead.
    private enum RootAlert: Identifiable {
        case askAssets
        case fetchDone(String)
        case fetchFailed(String)

        var id: String {
            switch self {
            case .askAssets:
                return "ask-assets"
            case .fetchDone(let report):
                return "done:" + report
            case .fetchFailed(let message):
                return "failed:" + message
            }
        }
    }

    @State private var alert: RootAlert?

    /// True while the launch fetch runs. The fetch is a minute of work with no
    /// other surface at this level, so it says so rather than looking frozen.
    @State private var fetchingAssets = false

    private enum Tab: Int {
        case search, downloads, accounts, settings, diagnostics
    }

    var body: some View {
        TabView(selection: $selection) {
            SearchScreen()
                .tabItem { Label("Search", systemImage: "magnifyingglass") }
                .tag(Tab.search.rawValue)

            DownloadsScreen()
                .tabItem { Label("Downloads", systemImage: "arrow.down.app") }
                .tag(Tab.downloads.rawValue)

            AccountsScreen()
                .tabItem { Label("Accounts", systemImage: "person.crop.circle") }
                .tag(Tab.accounts.rawValue)

            SettingsScreen()
                .tabItem { Label("Settings", systemImage: "gearshape") }
                .tag(Tab.settings.rawValue)

            if showDiagnostics {
                DiagnosticsScreen()
                    .tabItem { Label("Diagnostics", systemImage: "stethoscope") }
                    .tag(Tab.diagnostics.rawValue)
            }
        }
        // One toast for the whole app: a download finishes whether or not the
        // tab that started it is on screen.
        .overlay(alignment: .bottom) {
            if let toast = downloads.toast {
                ToastLine(text: toast)
            } else if fetchingAssets {
                ToastLine(text: "Fetching the signing components from Apple (~300 MB, once)...")
            }
        }
        .animation(.easeInOut(duration: 0.2), value: downloads.toast)
        .onAppear(perform: askAboutAssets)
        .alert(item: $alert) { item in alertContent(for: item) }
    }

    // MARK: - The signing components

    /// Asks, once per launch, whether to take the binaries this build does not
    /// carry -- and only of someone who already has an account.
    ///
    /// Two reasons for the account test. Someone who has signed in before and
    /// finds the cache empty is looking at a real event: iOS deleted a Caches
    /// directory it is allowed to evict, or the folder was removed by hand, and
    /// the next signed request will fail without those bytes. Asking then is the
    /// whole point. Someone setting the app up for the first time is not: they
    /// have not asked for anything yet, and a modal about 300 MB in the face of
    /// a person who has not even chosen an account is how an app gets
    /// uninstalled. That one is asked where the need actually appears, in the
    /// account sheet before the handshake (AccountsScreen), which is the same
    /// notice with the same button.
    ///
    /// The bridge holds the line either way: nothing downloads while the answer
    /// is no, so a missed question shows up as a refusal, not a bill.
    ///
    /// `stageIfNeeded` was already called by AppDelegate; this joins that run
    /// and reads the answer it leaves behind.
    private func askAboutAssets() {
        AssetStaging.stageIfNeeded(progress: nil) { _ in
            guard AppSession.shared.activeAccount != nil,
                  AssetStaging.needsConsent() else { return }

            Task { @MainActor in alert = .askAssets }
        }
    }

    private func fetchAssets() {
        fetchingAssets = true

        AssetStaging.resolveFromApple { report, error in
            Task { @MainActor in
                fetchingAssets = false

                if let error {
                    AppLog.error("launch fetch failed: " + error.localizedDescription, .assets)
                    alert = .fetchFailed(error.localizedDescription)
                } else {
                    AppLog.info("launch fetch finished: " + (report ?? "no report"), .assets)
                    alert = .fetchDone(report ?? "no report")
                }
            }
        }
    }

    private func alertContent(for item: RootAlert) -> Alert {
        switch item {
        case .askAssets:
            return Alert(title: Text("Fetch the signing components?"),
                         message: Text("This build does not carry the seven Apple binaries, "
                                       + "and DLiPA needs them to sign anything. Taking them "
                                       + "from Apple's macOS restore image costs about 300 MB "
                                       + "over roughly 6,200 requests -- a couple of minutes on "
                                       + "a phone, and once. Choosing Later leaves the app unable "
                                       + "to sign until you agree."),
                         primaryButton: .default(Text("Fetch now")) {
                             fetchAssets()
                         },
                         secondaryButton: .cancel(Text("Later")) {
                             AppLog.info("asset fetch declined at launch; signing stays "
                                         + "unavailable until it is agreed", .assets)
                         })
        case .fetchDone(let report):
            return Alert(title: Text("Signing components"),
                         message: Text(report),
                         dismissButton: .default(Text("OK")))
        case .fetchFailed(let message):
            return Alert(title: Text("Signing components"),
                         message: Text(message),
                         dismissButton: .default(Text("Try again")) {
                             fetchAssets()
                         })
        }
    }
}

/// One line in the capsule at the bottom of the screen.
private struct ToastLine: View {
    let text: String

    var body: some View {
        Text(text)
            .font(.subheadline)
            .padding(.horizontal, 16)
            .padding(.vertical, 10)
            .background(.regularMaterial, in: Capsule())
            .padding(.bottom, 68)
            .transition(.move(edge: .bottom).combined(with: .opacity))
    }
}
