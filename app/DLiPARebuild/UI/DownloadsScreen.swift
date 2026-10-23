import SwiftUI

struct DownloadsScreen: View {
    @State private var showShare = false
    @State private var shareURL: URL?

    var body: some View {
        NavigationView {
            EmptyStateView(
                title: "No Downloads",
                systemImage: "arrow.down.app",
                detail: "Finished downloads land here and can be shared or opened in TrollStore."
            )
            .navigationTitle("Downloads")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button {
                        showShare = shareURL != nil
                    } label: {
                        Image(systemName: "square.and.arrow.up")
                    }
                    .disabled(shareURL == nil)
                }
            }
        }
        .navigationViewStyle(.stack)
        .sheet(isPresented: $showShare) {
            if let shareURL {
                ActivityView(activityItems: [shareURL])
            }
        }
    }
}
