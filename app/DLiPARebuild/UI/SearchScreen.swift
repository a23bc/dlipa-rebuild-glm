import SwiftUI
import UIKit

/// Search, and the menu every result opens.
struct SearchScreen: View {
    @StateObject private var model = SearchModel()

    /// The result whose action sheet is open.
    @State private var actionTarget: StoreApp?
    /// The result whose version list is open, and whether picking a version
    /// there starts a download.
    @State private var versionTarget: StoreApp?
    @State private var versionPickEnabled = false
    /// The file or link the share sheet is showing.
    @State private var shareURL: URL?

    var body: some View {
        NavigationView {
            Group {
                if model.results.isEmpty {
                    EmptyStateView(
                        title: model.hasSearched ? "No Results" : "Search",
                        systemImage: "magnifyingglass",
                        detail: model.errorText ?? (model.hasSearched ? nil : "Look up an app by name, bundle identifier or App Store link."))
                } else {
                    List {
                        Section {
                            ForEach(model.results) { app in
                                Button { actionTarget = app } label: {
                                    SearchResultRow(app: app)
                                }
                                .buttonStyle(.plain)
                            }
                        } header: {
                            // A grouped list upper-cases its headers by
                            // default; the original shows "Results (38)".
                            Text("Results (\(model.results.count))")
                                .textCase(nil)
                        }
                    }
                    .listStyle(.insetGrouped)
                }
            }
            .navigationTitle("Search")
            .searchable(text: $model.term, prompt: "App, Bundle ID, Link")
            .onSubmit(of: .search) { Task { await model.run() } }
            .onChange(of: model.term) { value in
                // A cleared field goes back to the empty state instead of
                // leaving the last results on screen.
                if value.isEmpty { model.clear() }
            }
            .overlay {
                if model.busy {
                    ProgressView(model.status.isEmpty ? "Working..." : model.status)
                        .padding()
                        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12))
                }
            }
            .actionSheet(item: $actionTarget) { app in
                ActionSheet(title: Text(app.trackName),
                            message: Text(app.bundleId),
                            buttons: [
                                .default(Text("Download")) {
                                    Task { await model.download(app, versionID: nil) }
                                },
                                .default(Text("Download a specific version")) {
                                    versionPickEnabled = true
                                    versionTarget = app
                                },
                                .default(Text("Version history")) {
                                    versionPickEnabled = false
                                    versionTarget = app
                                },
                                .default(Text("Copy bundle ID")) {
                                    UIPasteboard.general.string = app.bundleId
                                },
                                .default(Text("Copy app ID")) {
                                    UIPasteboard.general.string = String(app.trackId)
                                },
                                .default(Text("Share")) {
                                    shareURL = URL(string: "https://apps.apple.com/app/id" + String(app.trackId))
                                },
                                .cancel()
                            ])
            }
            .sheet(item: $versionTarget, onDismiss: { versionTarget = nil }) { app in
                VersionListView(app: app, allowsDownload: versionPickEnabled) { versionID in
                    versionTarget = nil
                    Task { await model.download(app, versionID: versionID) }
                }
            }
            .sheet(item: Binding(get: { shareURL.map(ShareItem.init) },
                                 set: { if $0 == nil { shareURL = nil } })) { item in
                ActivityView(activityItems: [item.url])
            }
        }
        .navigationViewStyle(.stack)
    }
}

/// Wrapper so a plain URL can drive an item-based sheet.
struct ShareItem: Identifiable {
    let url: URL
    var id: String { url.absoluteString }
}

// MARK: - Row

/// Proportions follow the original app's search row: a 48 point icon, a 17
/// point semibold title that wraps to two lines, and one grey meta line under
/// it holding version, minimum iOS and download size.
private struct SearchResultRow: View {
    let app: StoreApp

    var body: some View {
        HStack(alignment: .center, spacing: 14) {
            ArtworkView(url: app.artworkUrl100 ?? app.artworkUrl60, size: 48)

            VStack(alignment: .leading, spacing: 4) {
                Text(app.trackName)
                    .font(.system(size: 17, weight: .semibold))
                    .foregroundColor(.primary)
                    .lineLimit(2)
                    .fixedSize(horizontal: false, vertical: true)

                if !app.metaText.isEmpty {
                    Text(app.metaText)
                        .font(.system(size: 13))
                        .foregroundColor(.secondary)
                        .lineLimit(1)
                }
            }

            Spacer(minLength: 0)
        }
        // The original's rows are about 75 points tall around a 48 point icon.
        .padding(.vertical, 12)
        .contentShape(Rectangle())
    }
}

/// Loads an icon. AsyncImage is iOS 15 and already caches through URLSession,
/// which is enough for a list that recycles rows.
private struct ArtworkView: View {
    let url: String?
    let size: CGFloat

    var body: some View {
        Group {
            if let url, let parsed = URL(string: url) {
                AsyncImage(url: parsed) { phase in
                    switch phase {
                    case .success(let image):
                        image.resizable().aspectRatio(contentMode: .fill)
                    default:
                        Rectangle().fill(Color.secondary.opacity(0.15))
                    }
                }
            } else {
                Rectangle().fill(Color.secondary.opacity(0.15))
            }
        }
        .frame(width: size, height: size)
        .clipShape(RoundedRectangle(cornerRadius: size * 0.23, style: .continuous))
    }
}

// MARK: - Model

@MainActor
final class SearchModel: ObservableObject {
    @Published var term = ""
    @Published private(set) var results: [StoreApp] = []
    @Published private(set) var busy = false
    @Published private(set) var status = ""
    @Published private(set) var errorText: String?
    @Published private(set) var hasSearched = false

    private var lastQuery = ""

    func clear() {
        results = []
        hasSearched = false
        errorText = nil
        lastQuery = ""
    }

    func run() async {
        let query = term.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !query.isEmpty else { return }
        guard query != lastQuery || results.isEmpty else { return }
        lastQuery = query
        busy = true
        status = "Searching..."
        errorText = nil
        defer { busy = false; status = "" }

        do {
            results = try await AppSession.shared.search(query)
            hasSearched = true
        } catch {
            results = []
            hasSearched = true
            errorText = error.localizedDescription
            AppLog.error("search failed: " + error.localizedDescription, .network)
        }
    }

    func download(_ app: StoreApp, versionID: String?) async {
        busy = true
        status = "Requesting " + app.trackName + "..."

        do {
            let name = app.bundleId + "-" + (versionID ?? "latest") + ".ipa"
            let file = try await AppSession.shared.download(app,
                                                           externalVersionId: versionID,
                                                           fileName: name) { _, _ in }
            status = "Saved " + file.lastPathComponent
            AppLog.info("download finished: " + file.lastPathComponent, .download)
        } catch {
            status = ""
            errorText = error.localizedDescription
            AppLog.error("download failed: " + error.localizedDescription, .download)
        }
        busy = false
    }
}
