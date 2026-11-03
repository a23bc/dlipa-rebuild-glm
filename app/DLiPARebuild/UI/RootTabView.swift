import SwiftUI

/// The app shell. Structure follows the dlipa-next attempt: one tab per job,
/// each with its own navigation stack, and an empty state that says what the
/// screen will show rather than a blank page.
/// Fades a screen in when its tab becomes visible.
///
/// TabView has no transition hook of its own -- switching tabs is a jump cut no
/// matter what is attached to the content -- so the fade runs on appearance
/// instead, which is the part that can be animated without replacing the bar.
private struct FadeIn: ViewModifier {
    @State private var shown = false

    func body(content: Content) -> some View {
        content
            .opacity(shown ? 1 : 0)
            .onAppear {
                withAnimation(.easeOut(duration: 0.18)) { shown = true }
            }
    }
}

struct RootTabView: View {
    /// Diagnostics is hidden until it is unlocked from Settings. SwiftUI gives
    /// no callback for tapping the tab bar itself, so the unlock lives on a
    /// row inside Settings instead of on the tab, which cannot be intercepted
    /// without replacing the whole tab bar.
    @AppStorage(SettingsScreen.showDiagnosticsKey) private var showDiagnostics = false
    @ObservedObject private var downloads = DownloadManager.shared

    var body: some View {
        TabView {
            SearchScreen().modifier(FadeIn())
                .tabItem { Label("Search", systemImage: "magnifyingglass") }
            DownloadsScreen().modifier(FadeIn())
                .tabItem { Label("Downloads", systemImage: "arrow.down.app") }
            AccountsScreen().modifier(FadeIn())
                .tabItem { Label("Accounts", systemImage: "person.crop.circle") }
            SettingsScreen().modifier(FadeIn())
                .tabItem { Label("Settings", systemImage: "gearshape") }
            if showDiagnostics {
                DiagnosticsScreen().modifier(FadeIn())
                    .tabItem { Label("Diagnostics", systemImage: "stethoscope") }
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
