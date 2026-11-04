import AVFoundation
import UIKit

/// Keeps the app able to answer while the installer fetches the package.
///
/// The install leaves the app: Safari opens for the trust page, then the system
/// installer fetches the manifest and the package from a server that lives in this
/// process. Once the app is suspended that server is unreachable, and the install
/// fails with nothing on screen to explain it.
///
/// Two things hold it up, and both are needed:
///
/// - `beginBackgroundTask` buys a few minutes of execution, which covers the
///   install itself, but it is bounded and ends when the system decides.
/// - A silent audio loop keeps the app in the audio background mode, which does
///   not expire. It is the part that survives the user switching to Settings to
///   trust the certificate and coming back.
final class BackgroundKeepAlive {
    static let shared = BackgroundKeepAlive()

    private var task: UIBackgroundTaskIdentifier = .invalid
    private var player: AVAudioPlayer?
    private var started = Date()

    /// Fallback track, used only if the bundled one is missing from the build.
    private static func writeSyntheticTrack() -> URL? {
        guard let wav = silentWAV(seconds: 60) else { return nil }

        let url = FileManager.default.temporaryDirectory.appendingPathComponent("keepalive.wav")
        try? wav.write(to: url)

        return url
    }

    private static func silentWAV(seconds: Int) -> Data? {
        let sampleRate = 8000
        let samples = sampleRate * seconds * 2 // 16-bit mono
        let dataSize = samples

        var data = Data()
        func append(_ value: UInt32) { withUnsafeBytes(of: value.littleEndian) { data.append(contentsOf: $0) } }
        func append16(_ value: UInt16) { withUnsafeBytes(of: value.littleEndian) { data.append(contentsOf: $0) } }

        data.append(contentsOf: Array("RIFF".utf8))
        append(UInt32(36 + dataSize))
        data.append(contentsOf: Array("WAVEfmt ".utf8))
        append(UInt32(16))          // PCM chunk size
        append16(UInt16(1))         // PCM
        append16(UInt16(1))         // mono
        append(UInt32(sampleRate))
        append(UInt32(sampleRate * 2))
        append16(UInt16(2))         // block align
        append16(UInt16(16))        // bits per sample
        data.append(contentsOf: Array("data".utf8))
        append(UInt32(dataSize))
        data.append(Data(count: dataSize))

        return data
    }

    /// Starts holding the app up. Safe to call repeatedly.
    func start(reason: String) {
        guard task == .invalid && player == nil else { return }

        started = Date()
        AppLog.info("background keep-alive on (" + reason + ")", .app)

        task = UIApplication.shared.beginBackgroundTask(withName: reason) { [weak self] in
            // Out of time: drop the task, the audio loop is what carries on.
            AppLog.warn("background task expiring", .app)
            self?.endTask()
        }

        do {
            let session = AVAudioSession.sharedInstance()
            try session.setCategory(.playback, mode: .default, options: [.mixWithOthers])
            try session.setActive(true)

            // The original app ships a blank track for exactly this purpose, and it
            // rides in the Go binary: the resource phase did not pick the file up,
            // and a keep-alive that quietly falls back to a synthesised track is
            // worse than carrying 300 KB.
            let cache = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
                .appendingPathComponent("dlipa", isDirectory: true).path

            var failure: NSError?
            let embedded = SapbridgeBlankAudioPath(cache, &failure)

            let url = embedded.flatMap(URL.init(fileURLWithPath:))
                ?? Bundle.main.url(forResource: "blank_audio", withExtension: "mp3")
                ?? BackgroundKeepAlive.writeSyntheticTrack()

            guard let url else { return }

            let player = try AVAudioPlayer(contentsOf: url)
            player.numberOfLoops = -1
            player.volume = 0
            player.play()
            self.player = player
        } catch {
            AppLog.warn("background keep-alive audio failed: " + error.localizedDescription, .app)
        }
    }

    /// Releases both holds. Called when the install ends or the app comes back.
    func stop() {
        guard task != .invalid || player != nil else { return }

        AppLog.info("background keep-alive off after "
                    + String(Int(Date().timeIntervalSince(self.started))) + "s", .app)

        player?.stop()
        player = nil
        try? AVAudioSession.sharedInstance().setActive(false, options: [.notifyOthersOnDeactivation])
        endTask()
    }

    private func endTask() {
        guard task != .invalid else { return }

        UIApplication.shared.endBackgroundTask(task)
        task = .invalid
    }
}
