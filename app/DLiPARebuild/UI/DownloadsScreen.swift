import SwiftUI
import UIKit

/// Downloads, running and finished, in one list.
///
/// A running job and a file on disk render with the same row, and a tap opens the
/// same menu the search results use. The row is deliberately **not** a Button:
/// wrapping it in one swallowed the swipe gesture, so swipe-to-delete only worked
/// once the list had reloaded from disk and the rows were no longer buttons.
struct DownloadsScreen: View {
    @State private var files: [URL] = []
    @State private var shareURL: URL?
    @State private var sheetTarget: SheetTarget?

    @ObservedObject private var manager = DownloadManager.shared

    var body: some View {
        NavigationView {
            Group {
                if files.isEmpty && manager.activeJobs.isEmpty {
                    EmptyStateView(
                        title: "No Downloads",
                        systemImage: "arrow.down.app",
                        detail: "Finished downloads land here and can be installed or shared."
                    )
                } else {
                    List {
                        ForEach(manager.activeJobs) { job in
                            DownloadJobRow(job: job)
                                .contentShape(Rectangle())
                                .onTapGesture { sheetTarget = .job(job) }
                        }

                        ForEach(files, id: \.self) { file in
                            FinishedRow(file: file)
                                .contentShape(Rectangle())
                                .onTapGesture { sheetTarget = .file(file) }
                        }
                        .onDelete { offsets in
                            for index in offsets {
                                delete(files[index])
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
            .onAppear { reload() }
            // One sheet, not two. Two `.actionSheet` modifiers on the same view
            // silently keep only the last, which is why finished rows stopped
            // responding while running ones still did.
            .actionSheet(item: $sheetTarget) { target in
                switch target {
                case .file(let url):
                    let item = DownloadTarget(url: url)
                    // Both lines in the title: ActionSheet draws its message
                    // after a blank row, which is the empty line that was
                    // showing under the subtitle.
                    return ActionSheet(title: Text(item.title + "\n" + item.subtitle),
                                       buttons: [
                                        .default(Text("Install")) { InstallMenu.present(url) },
                                        .default(Text("Install via local HTTPS")) { installOverHTTPS(url) },
                                        .default(Text("Share")) { shareURL = url },
                                        .cancel()
                                       ])
                case .job(let job):
                    return ActionSheet(title: Text(job.appName + "\n" + job.bundleID),
                                       buttons: [
                                        job.isPaused
                                            ? .default(Text("Resume")) { job.resume() }
                                            : .default(Text("Pause")) { job.pause() },
                                        .destructive(Text("Cancel download")) { manager.cancel(job) },
                                        .cancel()
                                       ])
                }
            }
            .sheet(item: Binding(get: { shareURL.map(ShareItem.init) },
                                 set: { if $0 == nil { shareURL = nil } })) { item in
                ActivityView(activityItems: [item.url])
            }
        }
    }

    private func delete(_ file: URL) {
        try? FileManager.default.removeItem(at: file)
        try? FileManager.default.removeItem(at: DownloadMetadataStore.sidecar(for: file))
    }

    private func reload() {
        files = AppSession.downloadedFiles()
    }
}

/// What the tap menu acts on: a file on disk, or a job still running.
private enum SheetTarget: Identifiable {
    case file(URL)
    case job(DownloadJob)

    var id: String {
        switch self {
        case .file(let url): return url.path
        case .job(let job): return job.id.uuidString
        }
    }
}

/// The menu contents for a finished file.
private struct DownloadTarget {
    let url: URL

    var title: String {
        DownloadMetadataStore.read(for: url)?.name
            ?? url.deletingPathExtension().lastPathComponent
    }

    /// Bundle id and version on one line, the way the search sheet does it.
    var subtitle: String {
        if let metadata = DownloadMetadataStore.read(for: url) {
            return metadata.bundleID + " · " + metadata.version
        }

        let parts = FinishedRow.split(url.deletingPathExtension().lastPathComponent)
        return parts.bundleID + (parts.version.isEmpty ? "" : " · " + parts.version)
    }
}

/// A download still running: icon, name, bundle id, version, size, progress.
private struct DownloadJobRow: View {
    @ObservedObject var job: DownloadJob

    var body: some View {
        HStack(spacing: 12) {
            Artwork(url: job.artworkURL, size: 48)

            VStack(alignment: .leading, spacing: 4) {
                Text(job.appName)
                    .font(.system(size: 17, weight: .semibold))
                    .lineLimit(1)
                Text(job.bundleID)
                    .font(.system(size: 13))
                    .foregroundColor(.secondary)
                    .lineLimit(1)

                if job.expected > 0 {
                    ProgressView(value: job.fraction)
                        .progressViewStyle(.linear)
                } else {
                    // The request half reports no bytes at all; a bar at zero
                    // there would read as "nothing is happening".
                    ProgressView()
                        .progressViewStyle(.linear)
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

/// A package on disk. Everything shown comes from the sidecar written when the
/// download finished, so a relaunch shows the same name, icon and version as the
/// job that produced it.
private struct FinishedRow: View {
    let file: URL

    var body: some View {
        let metadata = DownloadMetadataStore.read(for: file)
        let parts = FinishedRow.split(file.deletingPathExtension().lastPathComponent)

        HStack(spacing: 12) {
            Artwork(url: metadata?.artwork.flatMap(URL.init(string:)), size: 48)

            VStack(alignment: .leading, spacing: 4) {
                Text(metadata?.name ?? parts.bundleID)
                    .font(.system(size: 17, weight: .semibold))
                    .lineLimit(1)
                Text(metadata?.bundleID ?? parts.bundleID)
                    .font(.system(size: 13))
                    .foregroundColor(.secondary)
                    .lineLimit(1)
            }

            Spacer(minLength: 8)

            // Version above size, both on the trailing edge. Putting the
            // version beside the bundle id lost it behind long identifiers.
            VStack(alignment: .trailing, spacing: 2) {
                Text(metadata?.version ?? parts.version)
                    .font(.system(size: 13))
                    .foregroundColor(.secondary)
                Text(FinishedRow.size(of: file))
                    .font(.system(size: 12))
                    .foregroundColor(.secondary)
            }
        }
        .padding(.vertical, 12)
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

    /// Serves the package from the app and asks the installer to fetch it.
    ///
    /// The installer runs in another process, so the server has to outlive this
    /// call -- it does, the bridge keeps it alive for the process.
    private func installOverHTTPS(_ url: URL) {
        // Application Support, not Caches: iOS purges Caches whenever it likes, and a
        // regenerated certificate no longer matches the profile the user trusted.
        let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("dlipa", isDirectory: true)

        let cache = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("dlipa", isDirectory: true)

        // The certificate used to live in Caches. Move it rather than let a new one
        // be generated, which would silently invalidate the installed profile.
        try? FileManager.default.createDirectory(at: support, withIntermediateDirectories: true)

        for name in ["install-ca.pem", "install-cert.pem", "install-key.pem"] {
            let target = support.appendingPathComponent(name)
            let legacy = cache.appendingPathComponent(name)

            if !FileManager.default.fileExists(atPath: target.path),
               FileManager.default.fileExists(atPath: legacy.path) {
                try? FileManager.default.copyItem(at: legacy, to: target)
            }
        }

        let dataDir = support.path

        // Serve the patched copy when there is one: the untouched download has no
        // FairPlay data, so the installer takes it, then refuses it at verification --
        // which is exactly what "cannot install, try again later" looks like.
        let patched = url.deletingPathExtension().appendingPathExtension("patched.ipa")

        guard FileManager.default.fileExists(atPath: patched.path) else {
            // Refusing beats serving the raw download: the installer would take it,
            // download the whole thing and then reject it, which looks like a server
            // problem and reads like one in the log.
            AppLog.error("install: no patched copy for " + url.lastPathComponent, .download)

            return
        }

        let package = patched

        AppLog.info("install: serving " + package.lastPathComponent, .download)

        let metadata = DownloadMetadataStore.read(for: url)
        let parts = FinishedRow.split(url.deletingPathExtension().lastPathComponent)

        var failure: NSError?
        let target = SapbridgeStartInstallServer(dataDir,
                                                 package.path,
                                                 metadata?.bundleID ?? parts.bundleID,
                                                 metadata?.version ?? parts.version,
                                                 metadata?.name ?? parts.bundleID,
                                                 &failure)

        if let failure {
            AppLog.error("install server failed: " + failure.localizedDescription, .download)

            return
        }

        guard let target, let link = URL(string: target) else { return }

        AppLog.info("install via HTTPS: " + target, .download)

        // The installer runs in another process while this one is in the
        // background: without this the server stops answering the moment the user
        // leaves for Safari or Settings, and the install fails silently.
        BackgroundKeepAlive.shared.start(reason: "itms-services install")

        // Ask the server whether its own certificate is trusted before handing the
        // URL to the installer. Without this the failure is silence: the installer
        // tries, cannot verify the host, and stops -- nothing appears on screen to
        // say so.
        let probe = target
            .replacingOccurrences(of: "itms-services://?action=download-manifest&url=", with: "")
            .removingPercentEncoding

        guard let probeURL = probe.flatMap(URL.init(string:)) else { return }

        var request = URLRequest(url: probeURL)
        request.timeoutInterval = 5

        URLSession.shared.dataTask(with: request) { _, response, error in
            let trusted = error == nil && (response as? HTTPURLResponse)?.statusCode == 200

            // Which failure it was, not just "not trusted": a rejected certificate, an
            // unreachable host and a 404 all land here, and they need different fixes.
            let status = (response as? HTTPURLResponse)?.statusCode ?? -1
            var detail = "status \(status)"

            if let error = error as NSError? {
                detail = "error \(error.domain)/\(error.code): \(error.localizedDescription)"
            }

            DispatchQueue.main.async {
                if trusted {
                    UIApplication.shared.open(link)
                    return
                }

                AppLog.warn("install: probe failed (" + detail + "), showing the guide", .download)

                if let guide = SapbridgeInstallGuideURL(),
                   let guideURL = URL(string: guide) {
                    UIApplication.shared.open(guideURL)
                }
            }
        }.resume()
    }

/// "Open in…" for a local package. The document interaction controller is the
/// only supported way to hand a file to another app (TrollStore among them);
/// opening a file URL directly is refused.
enum InstallMenu {
    /// Held while the menu is up: the controller must outlive the call.
    private static var current: UIDocumentInteractionController?

    static func present(_ url: URL) {
        guard let scene = UIApplication.shared.connectedScenes.first as? UIWindowScene,
              let root = scene.keyWindow?.rootViewController else {
            return
        }

        let controller = UIDocumentInteractionController(url: url)
        current = controller
        controller.presentOpenInMenu(from: root.view.bounds, in: root.view, animated: true)
    }
}
