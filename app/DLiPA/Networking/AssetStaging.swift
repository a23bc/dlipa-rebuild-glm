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
        "AppleMediaServices": 14813888,
        "commerce": 8092640,
        "CoreFP": 94842464,
        "CoreFP.icxs": 7365344,
    ]

    /// Total bytes that have to be copied on a cold start.
    static let totalBytes: Int = {
        files.values.reduce(0, +)
    }()

    /// True once every file is staged and the bridge has been told where
    /// they live. Signing and downloading need this.
    static var isReady = false

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
        if isReady {
            DispatchQueue.main.async { completion(nil) }
            return
        }

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

            for (name, expectedSize) in files {
                let target = destination.appendingPathComponent(name)

                // iOS may purge the caches directory under disk pressure.
                // A size match means the file is present and complete.
                if let attributes = try? FileManager.default.attributesOfItem(
                    atPath: target.path),
                   (attributes[.size] as? Int) == expectedSize {
                    copied += expectedSize
                    AppLog.info("staged " + name + ", " + String(expectedSize) + " bytes", .assets)
                    progress?(Double(copied) / Double(totalBytes))
                    continue
                }

                guard let source = Bundle.main.url(forResource: name, withExtension: nil) else {
                    AppLog.error(name + " is missing from the app bundle", .assets)
                    firstError = AssetError.missingFromBundle(name)
                    break
                }

                // Remove a partial copy before writing again.
                if FileManager.default.fileExists(atPath: target.path) {
                    try? FileManager.default.removeItem(at: target)
                }

                do {
                    try FileManager.default.copyItem(at: source, to: target)
                    copied += expectedSize
                    progress?(Double(copied) / Double(totalBytes))
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
        if error == nil {
            // Only tell the bridge about the directory once every file is
            // there, so a partial set cannot be mistaken for a valid one.
            SapbridgeSetBundleDir(destination.path)
            isReady = true
        }
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
