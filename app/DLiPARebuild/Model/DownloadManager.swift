import Foundation

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

    private init() {}

    /// Starts a download and returns immediately.
    ///
    /// Nothing here awaits: the caller gets a job handle and the screen can be
    /// dismissed. The work continues on its own task, and the Downloads tab reads
    /// the job's published state.
    @discardableResult
    func start(_ app: StoreApp, versionID: String?) -> DownloadJob {
        let name = app.bundleId + "-" + (versionID ?? "latest") + ".ipa"
        let job = DownloadJob(app: app, versionID: versionID, fileName: name)

        jobs.insert(job, at: 0)

        AppLog.info("download queued: " + name, .download)

        Task { [weak job] in
            guard let job else { return }

            do {
                var ticks = 0

                let file = try await AppSession.shared.download(app,
                                                                externalVersionId: versionID,
                                                                fileName: name) { received, expected in
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

                job.finish(file.lastPathComponent, url: file)
                AppLog.info("download finished: " + file.lastPathComponent, .download)
                NotificationCenter.default.post(name: .downloadFinished, object: nil)
            } catch {
                job.fail(error.localizedDescription)
                AppLog.error("download failed: " + error.localizedDescription, .download)
            }
        }

        return job
    }

    /// The jobs still running, newest first, for the Downloads tab.
    var activeJobs: [DownloadJob] { jobs.filter(\.isActive) }
}

extension Notification.Name {
    /// Posted when a package lands on disk, so the Downloads list can reload.
    static let downloadFinished = Notification.Name("com.a23bc.dliparebuild.downloadFinished")
}
