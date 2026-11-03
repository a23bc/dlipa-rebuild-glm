import SwiftUI

/// Fades the tab that just became visible.
///
/// Keyed on the selection rather than on appearance: an `onAppear` fade only ran
/// the first time a tab was created, so switching away and back showed nothing.
/// The outgoing tab is already off screen by the time this runs, so zeroing its
/// opacity costs nothing.
private struct TabFade: ViewModifier {
    let tag: Int
    let selection: Int

    func body(content: Content) -> some View {
        content
            .opacity(selection == tag ? 1 : 0)
            .animation(.easeOut(duration: 0.18), value: selection)
    }
}

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

    private enum Tab: Int {
        case search, downloads, accounts, settings, diagnostics
    }

    var body: some View {
        TabView(selection: $selection) {
            SearchScreen()
                .modifier(TabFade(tag: Tab.search.rawValue, selection: selection))
                .tabItem { Label("Search", systemImage: "magnifyingglass") }
                .tag(Tab.search.rawValue)

            DownloadsScreen()
                .modifier(TabFade(tag: Tab.downloads.rawValue, selection: selection))
                .tabItem { Label("Downloads", systemImage: "arrow.down.app") }
                .tag(Tab.downloads.rawValue)

            AccountsScreen()
                .modifier(TabFade(tag: Tab.accounts.rawValue, selection: selection))
                .tabItem { Label("Accounts", systemImage: "person.crop.circle") }
                .tag(Tab.accounts.rawValue)

            SettingsScreen()
                .modifier(TabFade(tag: Tab.settings.rawValue, selection: selection))
                .tabItem { Label("Settings", systemImage: "gearshape") }
                .tag(Tab.settings.rawValue)

            if showDiagnostics {
                DiagnosticsScreen()
                    .modifier(TabFade(tag: Tab.diagnostics.rawValue, selection: selection))
                    .tabItem { Label("Diagnostics", systemImage: "stethoscope") }
                    .tag(Tab.diagnostics.rawValue)
            }
        }
        // One toast for the whole app: a download finishes whether or not the
        // tab that started it is on screen.
        .overlay(alignment: .bottom) {
            if let toast = downloads.toast {
                Text(toast)
                    .font(.subheadline)
                    .padding(.horizontal, 16)
                    .padding(.vertical, 10)
                    .background(.regularMaterial, in: Capsule())
                    .padding(.bottom, 68)
                    .transition(.move(edge: .bottom).combined(with: .opacity))
            }
        }
        .animation(.easeInOut(duration: 0.2), value: downloads.toast)
    }
}
