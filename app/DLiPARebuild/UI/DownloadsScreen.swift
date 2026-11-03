import SwiftUI

/// The packages already fetched, read straight from the Downloads folder.
///
/// There is no separate database: a file in the folder is a download, and
/// removing it here removes it from disk.
struct DownloadsScreen: View {
    @State private var files: [URL] = []
    @State private var shareURL: URL?

    /// Downloads run here whether or not the screen that started them is gone,
    /// so this is the one place their progress can be seen.
    @ObservedObject private var manager = DownloadManager.shared

    var body: some View {
        NavigationView {
            Group {
                if files.isEmpty && manager.jobs.isEmpty {
                    EmptyStateView(
                        title: "No Downloads",
                        systemImage: "arrow.down.app",
                        detail: "Finished downloads land here and can be shared or opened in TrollStore."
                    )
                } else {
                    List {
                        if !manager.jobs.isEmpty {
                            Section("In progress") {
                                ForEach(manager.jobs) { job in
                                    DownloadJobRow(job: job)
                                }
                            }
                        }

                        ForEach(files, id: \.self) { file in
                            Button { shareURL = file } label: {
                                row(for: file)
                            }
                            .buttonStyle(.plain)
                        }
                        .onDelete { offsets in
                            for index in offsets {
                                try? FileManager.default.removeItem(at: files[index])
                            }
                            reload()
                        }
                    }
                }
            }
            .navigationTitle("Downloads")
            .onReceive(NotificationCenter.default.publisher(for: .downloadFinished)) { _ in
                reload()
            }
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button { reload() } label: {
                        Image(systemName: "arrow.clockwise")
                    }
                }
            }
            .onAppear { reload() }
            .sheet(item: Binding(get: { shareURL.map(ShareItem.init) },
                                 set: { if $0 == nil { shareURL = nil } })) { item in
                ActivityView(activityItems: [item.url])
            }
        }
        .navigationViewStyle(.stack)
    }

    private func row(for file: URL) -> some View {
        HStack(spacing: 12) {
            Image(systemName: "shippingbox")
                .foregroundColor(.secondary)
                .frame(width: 24)
            VStack(alignment: .leading, spacing: 2) {
                Text(file.lastPathComponent)
                    .foregroundColor(.primary)
                    .lineLimit(1)
                Text(Self.sizeText(for: file))
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            Spacer(minLength: 4)
            Image(systemName: "square.and.arrow.up")
                .foregroundColor(.secondary)
        }
        .contentShape(Rectangle())
        .padding(.vertical, 2)
    }

    private func reload() {
        files = AppSession.downloadedFiles()
    }

    private static func sizeText(for file: URL) -> String {
        let values = try? file.resourceValues(forKeys: [.fileSizeKey])
        let bytes = Int64(values?.fileSize ?? 0)
        let formatter = ByteCountFormatter()
        formatter.countStyle = .file
        return formatter.string(fromByteCount: bytes)
    }
}

/// One job's progress. Separate view so each row observes its own job; the
/// manager's array only changes when a job is added, not as bytes arrive.
private struct DownloadJobRow: View {
    @ObservedObject var job: DownloadJob

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(job.appName).lineLimit(1)
                Spacer(minLength: 8)
                Text(job.statusText)
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .lineLimit(1)
            }

            if job.isActive {
                ProgressView(value: job.fraction)
            }
        }
        .padding(.vertical, 2)
    }
}
