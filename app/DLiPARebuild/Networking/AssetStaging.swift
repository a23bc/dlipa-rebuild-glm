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

    /// True while staging is in progress. Guards against concurrent
    /// stageIfNeeded invocations (AppDelegate and MainViewController both
    /// call it on launch).
    private static var isStaging = false
    private static let stagingLock = NSLock()

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
        if isReady || isStaging {
            stagingLock.unlock()
            DispatchQueue.main.async { completion(nil) }
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
                finish(firstError, destination: destination, completion: completion)
                return
            }

            for name in files {
                let target = destination.appendingPathComponent(name)

                // Always copy from the bundle. The Go bridge validates
                // SHA-256, and a stale file from a previous install (with a
                // different macOS version's binaries) would fail that check.
                // Copying every time is ~125 MB but only on cold start.

                // The Apple binaries live in the SapAssets/ subdirectory of the
                // bundle (staged there by scripts/stage-assets.sh and copied
                // as a folder reference in project.yml). Bundle.main.url(
                // forResource:withExtension:) does not search arbitrary
                // subdirectories by default, so pass subdirectory: "SapAssets".
                // Fall back to a bundle-wide search for safety.
                let source = Bundle.main.url(forResource: name, withExtension: nil, subdirectory: "SapAssets")
                    ?? Bundle.main.url(forResource: name, withExtension: nil)
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
        stagingLock.unlock()
        DispatchQueue.main.async { completion(error) }
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
