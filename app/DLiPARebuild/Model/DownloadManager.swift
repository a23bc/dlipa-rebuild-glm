import Foundation
import UIKit

/// One download, owned by the manager rather than by a screen.
///
/// The flow is two steps with very different lifetimes: the URL request runs the
/// emulated Store runtime for minutes, and the transfer that follows is ordinary
/// networking. Both used to run inside the screen that started them, which meant
/// the screen stayed busy for the whole thing and the progress was thrown away.
@MainActor
final class DownloadJob: ObservableObject, Identifiable {
    enum State: Equatable {
        case requesting
        case downloading
        case finished(String)
        case failed(String)
    }

    let id = UUID()
    let app: StoreApp
    /// nil means "whatever the store hands out today".
    let versionID: String?
    let fileName: String

    var appName: String { app.trackName }
    var bundleID: String { app.bundleId }
    /// The human version when the catalogue has one, else the id we asked for.
    var versionText: String {
        if let version = app.version, !version.isEmpty { return version }
        return versionID ?? "latest"
    }
    var artworkURL: URL? {
        URL(string: app.artworkUrl100 ?? app.artworkUrl60 ?? "")
    }

    @Published private(set) var state: State = .requesting
    @Published private(set) var isPaused = false

    /// Pause / cancel, once the task exists.
    let control = DownloadControl()
    /// Set when the package lands. The row turns into the finished row rather
    /// than a second entry being created for the same download.
    @Published private(set) var savedURL: URL?
    @Published private(set) var received: Int64 = 0
    @Published private(set) var expected: Int64 = 0

    init(app: StoreApp, versionID: String?, fileName: String) {
        self.app = app
        self.versionID = versionID
        self.fileName = fileName
    }

    var fraction: Double {
        guard expected > 0 else { return 0 }
        return min(1, Double(received) / Double(expected))
    }

    var isActive: Bool {
        switch state {
        case .requesting, .downloading: return true
        case .finished, .failed: return false
        }
    }

    var statusText: String {
        if isPaused { return "Paused" }

        switch state {
        case .requesting:
            return "Requesting"
        case .downloading:
            if expected > 0 {
                return DownloadJob.size(received) + " / " + DownloadJob.size(expected)
            }
            return DownloadJob.size(received)
        case .finished(let name):
            return "Saved " + name
        case .failed(let message):
            return message
        }
    }

    fileprivate func update(received: Int64, expected: Int64) {
        self.received = received
        if expected > 0 { self.expected = expected }
        if case .requesting = state { state = .downloading }
    }

    func pause() {
        isPaused = true
        control.pause()
    }

    func resume() {
        isPaused = false
        control.resume()
    }

    fileprivate func finish(_ name: String, url: URL) {
        savedURL = url
        state = .finished(name)
    }
    fileprivate func fail(_ message: String) { state = .failed(message) }

    static func size(_ bytes: Int64) -> String {
        let formatter = ByteCountFormatter()
        formatter.countStyle = .file
        return formatter.string(fromByteCount: bytes)
    }
}

/// Runs downloads for the whole app, so a screen can start one and go away.
@MainActor
final class DownloadManager: ObservableObject {
    static let shared = DownloadManager()

    @Published private(set) var jobs: [DownloadJob] = []

    /// Short-lived message shown over the app when a download lands. The row
    /// itself stays quiet: "Saved …" under the bundle id said nothing the row
    /// did not already show.
    @Published private(set) var toast: String?

    private init() {}

    /// Starts a download and returns immediately.
    ///
    /// Nothing here awaits: the caller gets a job handle and the screen can be
    /// dismissed. The work continues on its own task, and the Downloads tab reads
    /// the job's published state.
    @discardableResult
    func start(_ app: StoreApp, versionID: String?) -> DownloadJob {
        // bundle id and the version a person would recognise, not the numeric
        // identifier the catalogue uses internally.
        let version = app.version ?? versionID ?? "latest"
        let name = app.bundleId + "-" + version + ".ipa"
        let job = DownloadJob(app: app, versionID: versionID, fileName: name)

        jobs.insert(job, at: 0)

        AppLog.info("download queued: " + name, .download)

        Task { [weak job] in
            guard let job else { return }

            do {
                var ticks = 0

                let file = try await AppSession.shared.download(app,
                                                                externalVersionId: versionID,
                                                                fileName: name,
                                                                control: job.control) { received, expected in
                    ticks += 1

                    // First tick and every two hundred after it: enough to prove
                    // the callback arrives and what it carries, without filling
                    // the log at several calls a second.
                    if ticks == 1 || ticks % 200 == 0 {
                        AppLog.info("progress tick " + String(ticks) + ": "
                                    + String(received) + "/" + String(expected), .download)
                    }

                    // Called from a URLSession delegate queue, several times a
                    // second: hop to the main actor before touching state.
                    Task { @MainActor in job.update(received: received, expected: expected) }
                }

                DownloadMetadataStore.write(app, versionID: versionID, for: file)

                // Always: the package Apple serves has no FairPlay data, so an
                // unpatched download installs and then refuses to launch. The file is
                // patched in place -- there is no second copy to keep track of.
                var failure: NSError?
                _ = SapbridgePatchIPA(file.path,
                                      AppSession.shared.activeAccount?.email,
                                      &failure)

                if let failure {
                    AppLog.warn("ipa patch failed: " + failure.localizedDescription, .download)
                } else {
                    AppLog.info("ipa patched: " + file.lastPathComponent, .download)
                }
                job.finish(file.lastPathComponent, url: file)
                AppLog.info("download finished: " + file.lastPathComponent, .download)
                NotificationCenter.default.post(name: .downloadFinished, object: nil)

                // Done is felt before it is read.
                UINotificationFeedbackGenerator().notificationOccurred(.success)
                showToast(app.trackName + " downloaded")
            } catch {
                job.fail(error.localizedDescription)
                AppLog.error("download failed: " + error.localizedDescription, .download)
            }
        }

        return job
    }

    private func showToast(_ message: String) {
        toast = message

        Task { @MainActor in
            try? await Task.sleep(nanoseconds: 2_500_000_000)
            if toast == message { toast = nil }
        }
    }

    func cancel(_ job: DownloadJob) {
        job.control.cancel()
        jobs.removeAll { $0.id == job.id }
    }

    /// The jobs still running, newest first, for the Downloads tab.
    var activeJobs: [DownloadJob] { jobs.filter(\.isActive) }
}

extension Notification.Name {
    /// Posted when a package lands on disk, so the Downloads list can reload.
    static let downloadFinished = Notification.Name("com.a23bc.dliparebuild.downloadFinished")
}

/// What a finished file should look like after a relaunch.
///
/// The row needs a name, an icon and a version, and none of that survives in a
/// filename. Written beside the package as `<name>.json` so the Downloads list
/// reads the same for a file downloaded five minutes ago and one from last week.
struct DownloadMetadata: Codable {
    var name: String
    var bundleID: String
    var version: String
    var artwork: String?
}

enum DownloadMetadataStore {
    static func write(_ app: StoreApp, versionID: String?, for file: URL) {
        let metadata = DownloadMetadata(name: app.trackName,
                                        bundleID: app.bundleId,
                                        version: app.version ?? versionID ?? "latest",
                                        artwork: app.artworkUrl100 ?? app.artworkUrl60)

        guard let data = try? JSONEncoder().encode(metadata) else { return }
        try? data.write(to: sidecar(for: file))
    }

    static func read(for file: URL) -> DownloadMetadata? {
        guard let data = try? Data(contentsOf: sidecar(for: file)) else { return nil }
        return try? JSONDecoder().decode(DownloadMetadata.self, from: data)
    }

    static func sidecar(for file: URL) -> URL {
        file.deletingPathExtension().appendingPathExtension("json")
    }
}
