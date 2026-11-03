import SwiftUI

/// Downloads, running and finished, in one list.
///
/// There is no separate database: a file in the Downloads folder is a finished
/// download, a job in DownloadManager is one still going. Both render with the
/// same row so the list reads as one thing rather than two.
struct DownloadsScreen: View {
    @State private var files: [URL] = []
    @State private var shareURL: URL?

    /// Jobs run here whether or not the screen that started them still exists,
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
                        ForEach(manager.jobs) { job in
                            DownloadJobRow(job: job)
                        }

                        ForEach(files, id: \.self) { file in
                            Button { shareURL = file } label: {
                                FinishedRow(file: file)
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
                    .accessibilityLabel("Refresh")
                }
            }
            .onAppear { reload() }
            .sheet(item: Binding(get: { shareURL.map(ShareItem.init) },
                                 set: { if $0 == nil { shareURL = nil } })) { item in
                ActivityView(activityItems: [item.url])
            }
        }
    }

    private func reload() {
        files = AppSession.downloadedFiles()
    }
}

/// A download still running: icon, name, bundle id, version, size, progress.
private struct DownloadJobRow: View {
    @ObservedObject var job: DownloadJob

    var body: some View {
        HStack(spacing: 12) {
            Artwork(url: job.artworkURL, size: 44)

            VStack(alignment: .leading, spacing: 2) {
                Text(job.appName)
                    .lineLimit(1)
                Text(job.bundleID)
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .lineLimit(1)

                if job.isActive {
                    // Indeterminate while the size is unknown: the request half
                    // reports no bytes at all, and a zero-width bar there reads
                    // as "nothing is happening".
                    if job.expected > 0 {
                        ProgressView(value: job.fraction)
                            .progressViewStyle(.linear)
                    } else {
                        ProgressView()
                            .progressViewStyle(.linear)
                    }
                }

                Text(job.statusText)
                    .font(.caption2)
                    .foregroundColor(.secondary)
                    .lineLimit(1)
            }

            Spacer(minLength: 8)

            VStack(alignment: .trailing, spacing: 2) {
                Text(job.versionText)
                    .font(.caption)
                    .foregroundColor(.secondary)
                if job.expected > 0 {
                    Text(DownloadJob.size(job.expected))
                        .font(.caption2)
                        .foregroundColor(.secondary)
                }
            }
        }
        .padding(.vertical, 2)
    }
}

/// A package on disk. The name carries the bundle id and the version, so the row
/// reads them back out of it rather than keeping a side table.
private struct FinishedRow: View {
    let file: URL

    var body: some View {
        let parts = FinishedRow.split(file.deletingPathExtension().lastPathComponent)

        HStack(spacing: 12) {
            Artwork(url: nil, size: 44)

            VStack(alignment: .leading, spacing: 2) {
                Text(parts.bundleID.isEmpty ? file.lastPathComponent : parts.bundleID)
                    .lineLimit(1)
                Text(file.lastPathComponent)
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .lineLimit(1)
            }

            Spacer(minLength: 8)

            VStack(alignment: .trailing, spacing: 2) {
                Text(parts.version)
                    .font(.caption)
                    .foregroundColor(.secondary)
                Text(FinishedRow.size(of: file))
                    .font(.caption2)
                    .foregroundColor(.secondary)
            }
        }
        .contentShape(Rectangle())
        .padding(.vertical, 2)
    }

    /// "com.example.app-1.2.3" -> ("com.example.app", "1.2.3").
    static func split(_ stem: String) -> (bundleID: String, version: String) {
        guard let dash = stem.range(of: "-", options: .backwards) else {
            return (stem, "")
        }

        return (String(stem[stem.startIndex..<dash.lowerBound]),
                String(stem[dash.upperBound...]))
    }

    static func size(of file: URL) -> String {
        let values = try? file.resourceValues(forKeys: [.fileSizeKey])
        let formatter = ByteCountFormatter()
        formatter.countStyle = .file
        return formatter.string(fromByteCount: Int64(values?.fileSize ?? 0))
    }
}

/// The same rounded artwork the search rows use.
private struct Artwork: View {
    let url: URL?
    let size: CGFloat

    var body: some View {
        Group {
            if let url {
                AsyncImage(url: url) { image in
                    image.resizable().aspectRatio(contentMode: .fill)
                } placeholder: {
                    Color.secondary.opacity(0.15)
                }
            } else {
                Image(systemName: "shippingbox")
                    .font(.system(size: size * 0.45))
                    .foregroundColor(.secondary)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .background(Color.secondary.opacity(0.15))
            }
        }
        .frame(width: size, height: size)
        .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
    }
}
