import SwiftUI

/// The version list for one app.
///
/// Apple has no version endpoint: the identifiers come back inside the
/// download-product response, so opening this sheet performs that request and
/// keeps only the metadata.
struct VersionListView: View {
    let app: StoreApp
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
                                        // A blank keeps the line's height, so the
                                        // identifier does not jump down when the
                                        // version arrives.
                                        Text(titles[identifier] ?? " ")
                                            .foregroundColor(.primary)
                                        Text(identifier)
                                            .font(.caption)
                                            .foregroundColor(.secondary)
                                    }
                                    Spacer()
                                }
                                .contentShape(Rectangle())
                            }
                            // Resolved when the row is reached, not when the sheet
                            // opens: a long history should cost nothing until it is
                            // scrolled through.
                            .onAppear { enqueue(identifier) }
                        }
                    }
                }
            }
            .navigationTitle("Version History")
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

    /// Rows waiting for their version. The most recent arrival is served first: after
    /// scrolling, what is on screen is what is being waited on, not whatever was
    /// queued before the scroll.
    @State private var queue: [String] = []
    @State private var inFlight = 0

    /// Two at a time. One left the list crawling; more than two put enough signed
    /// requests in flight to make the sheet stutter.
    private let workers = 2

    private func enqueue(_ identifier: String) {
        guard titles[identifier] == nil, !queue.contains(identifier) else { return }

        queue.insert(identifier, at: 0)
        pump()
    }

    private func pump() {
        while inFlight < workers, let next = queue.first {
            queue.removeFirst()
            inFlight += 1

            Task {
                let version = await AppSession.shared.versionString(for: app, versionID: next)

                if let version {
                    titles[next] = version
                }

                inFlight -= 1
                pump()
            }
        }
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
