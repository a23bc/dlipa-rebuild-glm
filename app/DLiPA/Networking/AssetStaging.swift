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
                    // Log the source path, size and sha256 so a mismatch
                    // between the bundle's bytes and the pinned digest is
                    // visible in the device log without needing to repackage
                    // the IPA to inspect it. The Go side's validate() will
                    // also print the sha256, but only after every file has
                    // been staged; per-file logging here localises the bad
                    // file to its source path.
                    let stagedSha = sha256(ofFile: target.path)
                    let sourceSha = sha256(ofFile: source.path)
                    AppLog.info(
                        "staged " + name + " source=" + source.path
                            + " size=" + String(sz)
                            + " source-sha256=" + sourceSha
                            + " staged-sha256=" + stagedSha,
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

extension AssetStaging {
    /// SHA-256 of the file at `path`, lowercase hex, or "<err>" on failure.
    /// Uses CommonCrypto because CryptoKit requires iOS 13+ and the project
    /// deployment target is iOS 15 (fine), but CommonCrypto is already
    /// linked and avoids pulling another framework into the bridge header.
    static func sha256(ofFile path: String) -> String {
        guard let handle = FileHandle(forReadingAtPath: path) else {
            return "<no-file>"
        }
        defer { try? handle.close() }

        var context = CC_SHA256_CTX()
        CC_SHA256_Init(&context)
        let chunkSize = 1 << 20  // 1 MB
        while true {
            let data = handle.readData(ofLength: chunkSize)
            if data.isEmpty { break }
            data.withUnsafeBytes { (buf: UnsafeRawBufferPointer) in
                _ = CC_SHA256_Update(&context, buf.baseAddress, CC_LONG(buf.count))
            }
        }
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        _ = CC_SHA256_Final(&digest, &context)
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}
