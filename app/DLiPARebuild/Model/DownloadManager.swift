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
    /// The human version of the build that was asked for.
    ///
    /// A specific version is not the catalogue version: the app object carries the
    /// one the store hands out today, so using it labelled every old build with the
    /// newest number. Until the build's own version is resolved the identifier is
    /// shown, because it is at least true.
    var versionText: String {
        if let versionID {
            return resolvedVersion ?? versionID
        }

        if let version = app.version, !version.isEmpty { return version }

        return "latest"
    }

    /// Filled in once the build's marketing version has been fetched.
    @Published private(set) var resolvedVersion: String?

    func resolveVersion(_ version: String?) {
        guard resolvedVersion == nil, let version, !version.isEmpty else { return }

        resolvedVersion = version
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
        // A pinned build is named after its identifier: app.version is the version
        // the store hands out today, and putting that in the file name labelled every
        // old build with the newest number.
        let version = versionID ?? app.version ?? "latest"
        let name = app.bundleId + "-" + version + ".ipa"
        let job = DownloadJob(app: app, versionID: versionID, fileName: name)

        jobs.insert(job, at: 0)

        // Resolve the label in the background: the identifier is what was asked for,
        // the marketing version is what a person recognises.
        if let versionID {
            Task { [weak job] in
                let resolved = await AppSession.shared.versionString(for: app,
                                                                    versionID: versionID)
                job?.resolveVersion(resolved)
            }
        }

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

                // Written after the patch: the package now says what it needs, and the
                // deployment target comes from the package rather than from a catalogue
                // field that may be missing.
                let identity = DownloadIdentity.read(besideFile: file)
                DownloadMetadataStore.write(app,
                                            version: job.versionText,
                                            minimumOS: identity?.minimumOS ?? app.minimumOsVersion,
                                            for: file)

                if let artwork = URL(string: app.artworkUrl100 ?? app.artworkUrl60 ?? "") {
                    Task {
                        guard let (data, _) = try? await URLSession.shared.data(from: artwork) else { return }
                        DownloadMetadataStore.attachArtwork(data, for: file)
                    }
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

/// What the package said about itself when the patch ran.
///
/// Written by the bridge beside the package and consumed once: the deployment target
/// is in here, and reading it from the package each time a row is drawn would mean
/// opening a 350 MB archive to look at a four kilobyte plist.
struct DownloadIdentity: Decodable {
    let bundleID: String
    let version: String
    let minimumOS: String
    let title: String
    let size: Int64

    static func read(besideFile file: URL) -> DownloadIdentity? {
        let path = URL(fileURLWithPath: file.path + ".identity.json")

        guard let data = try? Data(contentsOf: path) else { return nil }

        try? FileManager.default.removeItem(at: path)

        return try? JSONDecoder().decode(DownloadIdentity.self, from: data)
    }
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
    /// The iOS the app requires, read out of the package. Optional so sidecars
    /// written before it existed still decode.
    var minimumOS: String?
    /// The icon itself, so the list does not need the network to draw a row that has
    /// been sitting there for weeks.
    var artworkData: Data?
}

enum DownloadMetadataStore {
    static func write(_ app: StoreApp, version: String, minimumOS: String?, for file: URL) {
        let metadata = DownloadMetadata(name: app.trackName,
                                        bundleID: app.bundleId,
                                        version: version,
                                        artwork: app.artworkUrl100 ?? app.artworkUrl60,
                                        minimumOS: minimumOS,
                                        artworkData: nil)

        guard let data = try? PropertyListEncoder().encode(metadata) else { return }
        try? data.write(to: sidecar(for: file))
    }

    /// Stores the icon inside the sidecar, so a row does not go to the network for a
    /// package that was downloaded weeks ago.
    static func attachArtwork(_ data: Data, for file: URL) {
        guard var metadata = read(for: file) else { return }

        metadata.artworkData = data

        guard let encoded = try? PropertyListEncoder().encode(metadata) else { return }
        try? encoded.write(to: sidecar(for: file))
    }

    static func read(for file: URL) -> DownloadMetadata? {
        if let data = try? Data(contentsOf: sidecar(for: file)),
           let metadata = try? PropertyListDecoder().decode(DownloadMetadata.self, from: data) {
            return metadata
        }

        // Older sidecars are .json beside the package, and some of those were written
        // as a plist under the wrong extension -- the decoder is tried against both
        // rather than assuming.
        let legacy = file.deletingPathExtension().appendingPathExtension("json")

        if let data = try? Data(contentsOf: legacy) {
            if let metadata = try? PropertyListDecoder().decode(DownloadMetadata.self, from: data) {
                return metadata
            }

            return try? JSONDecoder().decode(DownloadMetadata.self, from: data)
        }

        return nil
    }

    static func sidecar(for file: URL) -> URL {
        file.deletingPathExtension().appendingPathExtension("plist")
    }
}
