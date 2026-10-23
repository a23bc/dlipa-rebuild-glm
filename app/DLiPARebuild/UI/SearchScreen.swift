import SwiftUI

struct SearchScreen: View {
    @State private var term = ""

    var body: some View {
        NavigationView {
            EmptyStateView(
                title: "Search",
                systemImage: "magnifyingglass",
                detail: "Look up an app by name, bundle identifier or App Store link."
            )
            .searchable(text: $term, prompt: "App, Bundle ID, Link")
            .navigationTitle("Search")
        }
        .navigationViewStyle(.stack)
    }
}
