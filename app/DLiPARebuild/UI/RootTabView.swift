import SwiftUI

/// The app shell. Structure follows the dlipa-next attempt: one tab per job,
/// each with its own navigation stack, and an empty state that says what the
/// screen will show rather than a blank page.
struct RootTabView: View {
    var body: some View {
        TabView {
            SearchScreen()
                .tabItem { Label("Search", systemImage: "magnifyingglass") }
            DownloadsScreen()
                .tabItem { Label("Downloads", systemImage: "arrow.down.app") }
            AccountsScreen()
                .tabItem { Label("Accounts", systemImage: "person.crop.circle") }
            DiagnosticsScreen()
                .tabItem { Label("Diagnostics", systemImage: "stethoscope") }
            SettingsScreen()
                .tabItem { Label("Settings", systemImage: "gearshape") }
        }
    }
}
