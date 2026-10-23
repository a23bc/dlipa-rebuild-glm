import SwiftUI

/// The packages already fetched, read straight from the Downloads folder.
///
/// There is no separate database: a file in the folder is a download, and
/// removing it here removes it from disk.
struct DownloadsScreen: View {
    @State private var files: [URL] = []
    @State private var shareURL: URL?

    var body: some View {
        NavigationView {
            Group {
                if files.isEmpty {
                    EmptyStateView(
                        title: "No Downloads",
                        systemImage: "arrow.down.app",
                        detail: "Finished downloads land here and can be shared or opened in TrollStore."
                    )
                } else {
                    List {
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
