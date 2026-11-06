import Foundation

/// Copies the bundled Apple SAP binaries into the caches directory and
/// points the Go bridge at them.
///
/// The four binaries are about 119 MB, so staging happens off the main
/// thread and reports progress. The Go loader validates size and SHA-256,
/// so a truncated or corrupt copy is rejected here rather than surfacing
/// later as an opaque SAP handshake error.
enum AssetStaging {
    private static let files = [
        "AppleMediaServices",
        "commerce",
        "CoreFP",
        "CoreFP.icxs",
    ]

    /// Total bytes that have to be copied on a cold start (approximate, for
    /// progress display only).
    static let totalBytes: Int = 125_000_000

    /// True once every file is staged and the bridge has been told where
    /// they live. Signing and downloading need this.
    static var isReady = false

    /// True when this build ships without the four binaries. That is now a
    /// normal build, not a broken one: the bridge resolves them from Apple's
    /// restore image the first time something needs them, so staging has
    /// nothing to copy and must not point the bridge at an empty directory --
    /// an explicit BundleDir is checked before the fallback and would fail
    /// there, hiding the download behind a "file not found".
    private(set) static var resolvesOnDemand = false

    /// True while staging is in progress. Guards against concurrent
    /// stageIfNeeded invocations (AppDelegate and MainViewController both
    /// call it on launch).
    private static var isStaging = false
    private static let stagingLock = NSLock()

    /// Callers that arrived while a staging run was already in flight. They are
    /// answered when that run finishes, with the same error the first caller
    /// gets -- returning nil to them meant "ready" before anything was copied.
    private static var waiters: [(Error?) -> Void] = []

    static var stagedDirectory: URL {
        FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("SapAssets", isDirectory: true)
    }

    /// Stages the assets in the background.
    ///
    /// @param progress called on a background queue with 0...1, or nil.
    /// @param completion called on the main queue once, with an error if
    ///   staging failed. Safe to call more than once; the work is skipped.
    static func stageIfNeeded(
        progress: ((Double) -> Void)? = nil,
        completion: @escaping (Error?) -> Void
    ) {
        // Protect against concurrent invocations (AppDelegate and
        // MainViewController both call this on launch). The lock ensures
        // only one staging task runs; subsequent callers wait and then
        // see isReady=true.
        stagingLock.lock()
        if isReady || resolvesOnDemand {
            stagingLock.unlock()
            DispatchQueue.main.async { completion(nil) }
            return
        }
        if isStaging {
            // Somebody else is copying. Wait for that run instead of reporting
            // success for a directory that is still being filled.
            waiters.append(completion)
            stagingLock.unlock()
            return
        }
        isStaging = true
        stagingLock.unlock()

        let destination = stagedDirectory

        DispatchQueue.global(qos: .utility).async {
            var firstError: Error?
            var copied = 0

            do {
                try FileManager.default.createDirectory(
                    at: destination, withIntermediateDirectories: true)
            } catch {
                // firstError is still nil here, so passing it told finish() the
                // staging had succeeded: it set isReady, pointed the bridge at a
                // directory that does not exist, and answered nil.
                finish(error, destination: destination, completion: completion)
                return
            }

            // A build that ships no binaries at all is not a broken build: the
            // bridge resolves them on first use. Answer every caller with nil,
            // because staging genuinely has nothing left to do.
            guard bundledSource(for: files[0]) != nil else {
                AppLog.info(
                    "SAP assets are not bundled; the bridge resolves them on first use",
                    .assets)
                finishWithoutAssets(completion: completion)
                return
            }

            for name in files {
                let target = destination.appendingPathComponent(name)

                // Always copy from the bundle. The Go bridge validates
                // SHA-256, and a stale file from a previous install (with a
                // different macOS version's binaries) would fail that check.
                // Copying every time is ~125 MB but only on cold start.

                let source = bundledSource(for: name)
                guard let source else {
                    AppLog.error(name + " is missing from the app bundle", .assets)
                    firstError = AssetError.missingFromBundle(name)
                    break
                }

                // Log start *before* the copy so a hang is localisable to a
                // specific file. CoreFP is ~95 MB and on older devices the
                // copy can take noticeable time; without this line the UI just
                // shows "Waiting for the signing assets to finish staging"
                // with no indication of which file is in flight.
                let sourceSize = (try? FileManager.default.attributesOfItem(atPath: source.path)[.size] as? Int) ?? 0
                AppLog.info(
                    "staging " + name + " start source=" + source.path
                        + " size=" + String(sourceSize),
                    .assets
                )

                // Remove a partial copy before writing again.
                if FileManager.default.fileExists(atPath: target.path) {
                    try? FileManager.default.removeItem(at: target)
                }

                do {
                    try FileManager.default.copyItem(at: source, to: target)
                    let attrs = try? FileManager.default.attributesOfItem(atPath: target.path)
                    let sz = (attrs?[.size] as? Int) ?? 0
                    copied += max(sz, 1)
                    progress?(Double(copied) / Double(totalBytes))
                    // SHA-256 is intentionally NOT computed here: on older
                    // devices hashing 95 MB twice (source + staged) added
                    // 30-60 seconds per file and made staging appear to hang.
                    // The Go side's validate() already prints actual vs
                    // expected sha256 on mismatch, which is sufficient for
                    // diagnosing a bad bundle.
                    AppLog.info(
                        "staged " + name + " size=" + String(sz)
                            + " cumulative=" + String(copied) + "/" + String(totalBytes),
                        .assets
                    )
                } catch {
                    AppLog.error("failed to stage " + name + ": " + String(describing: error), .assets)
                    firstError = error
                    break
                }
            }

            finish(firstError, destination: destination, completion: completion)
        }
    }

    private static func finish(_ error: Error?,
                               destination: URL,
                               completion: @escaping (Error?) -> Void) {
        AppLog.info("all " + String(files.count) + " assets staged to " + destination.path, .assets)
        stagingLock.lock()
        if error == nil {
            // Only tell the bridge about the directory once every file is
            // there, so a partial set cannot be mistaken for a valid one.
            SapbridgeSetBundleDir(destination.path)
            isReady = true
        }
        isStaging = false
        let pending = waiters
        waiters.removeAll()
        stagingLock.unlock()
        DispatchQueue.main.async {
            completion(error)
            for waiter in pending { waiter(error) }
        }
    }

    /// The bundle lookup, in one place: the binaries sit in a SapAssets/
    /// subdirectory (added as a folder reference by project.yml), and
    /// `url(forResource:withExtension:)` does not search subdirectories
    /// unless told, so pass it and keep a bundle-wide search as a fallback.
    private static func bundledSource(for name: String) -> URL? {
        Bundle.main.url(forResource: name, withExtension: nil, subdirectory: "SapAssets")
            ?? Bundle.main.url(forResource: name, withExtension: nil)
    }

    /// Answers like finish() but without claiming a staged directory: neither
    /// BundleDir nor isReady may be touched here, because there is nothing for
    /// the bridge to read from this bundle.
    private static func finishWithoutAssets(completion: @escaping (Error?) -> Void) {
        stagingLock.lock()
        resolvesOnDemand = true
        isStaging = false
        let pending = waiters
        waiters.removeAll()
        stagingLock.unlock()
        DispatchQueue.main.async {
            completion(nil)
            for waiter in pending { waiter(nil) }
        }
    }
}

enum AssetError: LocalizedError {
    case missingFromBundle(String)

    var errorDescription: String? {
        switch self {
        case .missingFromBundle(let name):
            return name + " is not in the app bundle";
        }
    }
}
