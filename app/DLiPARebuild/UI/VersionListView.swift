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
                        ForEach(Array(versions.identifiers.enumerated()), id: \.offset) { entry in
                            Button {
                                guard allowsDownload else { return }
                                onPick(entry.element)
                            } label: {
                                HStack {
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(entry.element == versions.latest ? "Latest" : entry.element)
                                            .foregroundColor(.primary)
                                        if entry.element == versions.latest {
                                            Text(entry.element)
                                                .font(.caption)
                                                .foregroundColor(.secondary)
                                        }
                                    }
                                    Spacer()
                                    if entry.element == versions.latest {
                                        Image(systemName: "checkmark")
                                            .foregroundColor(.accentColor)
                                    }
                                }
                                .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                        }
                    }
                }
            }
            .navigationTitle(allowsDownload ? "Pick a Version" : "Version History")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Done") { dismiss() }
                }
            }
        }
        .navigationViewStyle(.stack)
        .task { await load() }
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
