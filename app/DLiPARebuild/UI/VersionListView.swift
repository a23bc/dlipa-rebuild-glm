import SwiftUI

/// The version list for one app.
///
/// Apple has no version endpoint: the identifiers come back inside the
/// download-product response, so opening this sheet performs that request and
/// keeps only the metadata.
struct VersionListView: View {
    let app: StoreApp
    /// When false the list is read-only history; when true a tap starts a
    /// download of that version.
    let allowsDownload: Bool
    var onPick: (String) -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var versions: AppStoreClient.VersionList?
    /// Resolved marketing versions, filled in as rows appear.
    @State private var titles: [String: String] = [:]
    @State private var errorText: String?
    @State private var loading = true

    var body: some View {
        NavigationView {
            Group {
                if loading {
                    ProgressView("Loading...")
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else if let errorText {
                    EmptyStateView(title: "Failed", systemImage: "exclamationmark.triangle",
                                   detail: errorText)
                } else if let versions {
                    List {
                        ForEach(ordered(versions), id: \.self) { identifier in
                            // Tapping always starts that version's download, in
                            // history as well: the list is the only place a
                            // specific build can be chosen, and doing nothing on
                            // tap made it look broken.
                            Button {
                                onPick(identifier)
                                dismiss()
                            } label: {
                                HStack {
                                    VStack(alignment: .leading, spacing: 2) {
                                        // The marketing version is what a person
                                        // recognises; the identifier is the only
                                        // value a caller can use, so it stays
                                        // visible underneath.
                                        Text(titles[identifier] ?? identifier)
                                            .foregroundColor(.primary)
                                        Text("ID " + identifier)
                                            .font(.caption)
                                            .foregroundColor(.secondary)
                                    }
                                    Spacer()
                                    if identifier == versions.latest {
                                        Image(systemName: "checkmark")
                                            .foregroundColor(.accentColor)
                                    }
                                }
                                .contentShape(Rectangle())
                            }
                            .task {
                                if titles[identifier] == nil {
                                    titles[identifier] = await AppSession.shared
                                        .versionString(for: app, versionID: identifier)
                                }
                            }
                        }
                    }
                }
            }
            .navigationTitle(allowsDownload ? "Pick a Version" : "Version History")
            .navigationBarTitleDisplayMode(.large)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Done") { dismiss() }
                }
            }
        }
        .navigationViewStyle(.stack)
        .task { await load() }
    }

    /// Newest first: the latest identifier, then the rest by descending id, which is
    /// chronological -- Apple increments these as builds ship.
    private func ordered(_ list: AppStoreClient.VersionList) -> [String] {
        list.identifiers.sorted { left, right in
            if left == list.latest { return true }
            if right == list.latest { return false }

            return (Int64(left) ?? 0) > (Int64(right) ?? 0)
        }
    }

    private func load() async {
        loading = true
        errorText = nil
        defer { loading = false }
        do {
            versions = try await AppSession.shared.versions(for: app)
        } catch {
            errorText = error.localizedDescription
            AppLog.error("version lookup failed: " + error.localizedDescription, .download)
        }
    }
}
