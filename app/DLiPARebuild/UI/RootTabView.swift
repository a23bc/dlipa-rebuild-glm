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

    var body: some View {
        TabView {
            SearchScreen()
                .tabItem { Label("Search", systemImage: "magnifyingglass") }
            DownloadsScreen()
                .tabItem { Label("Downloads", systemImage: "arrow.down.app") }
            AccountsScreen()
                .tabItem { Label("Accounts", systemImage: "person.crop.circle") }
            SettingsScreen()
                .tabItem { Label("Settings", systemImage: "gearshape") }
            if showDiagnostics {
                DiagnosticsScreen()
                    .tabItem { Label("Diagnostics", systemImage: "stethoscope") }
            }
        }
    }
}
