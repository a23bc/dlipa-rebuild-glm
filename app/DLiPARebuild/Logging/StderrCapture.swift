import Foundation

/// Black-box recorder for the Go runtime's fatal-error output.
///
/// ## Why this exists
///
/// The SAP bridge calls into Apple's Mach-O binaries via the Unicorn CPU
/// emulator. Unicorn is a C library invoked through cgo. When a synchronous
/// signal (SIGSEGV / SIGBUS / SIGABRT) fires inside cgo code, the Go runtime
/// catches it, prints
///
///     fatal error: signal: SIGSEGV
///     goroutine 1 [syscall]:
///     ...stack trace...
///
/// to **fd 2 (stderr)**, and calls `exit(2)`. The Swift-side `recover()`
/// wrappers in `SAPSigner.swift` cannot intercept this — `recover()` only
/// catches Go-level panics, not cgo signals. The process dies, atexit
/// handlers fire, and no crash report is generated.
///
/// iOS captures stderr writes in the system log, but heavily redacts them
/// to `<private>`. The actual fatal-error message is invisible to the
/// user's `log stream` capture.
///
/// ## What this does
///
/// 1. On launch, before any SAP code runs, check whether a previous
///    session left a `dlipa-stderr.log` in Caches.
/// 2. If yes, archive it to `dlipa-stderr-previous.log` and dump its
///    contents line-by-line into `AppLog.error` so the user can see what
///    killed the previous launch via the in-app **Share log** button.
/// 3. Truncate `dlipa-stderr.log` and `freopen` fd 2 (stderr) onto it.
///    Every subsequent `fmt.Fprintf(os.Stderr, …)` from the Go side, and
///    every Go runtime `fatal error:` print, lands in this file.
/// 4. When the process dies (via signal or normal exit), the OS closes
///    the file. The next launch reads it back as in step 2.
///
/// This is the standard "flight recorder" pattern: lose nothing on
/// crash, surface it on next launch.
enum StderrCapture {

    /// The file that receives stderr for the *current* launch.
    static var currentLogURL: URL {
        FileManager.default
            .urls(for: .cachesDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("dlipa-stderr.log")
    }

    /// The file that received stderr for the *previous* launch.
    static var previousLogURL: URL {
        FileManager.default
            .urls(for: .cachesDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("dlipa-stderr-previous.log")
    }

    /// Call this at the very start of `AppDelegate.didFinishLaunchingWithOptions`,
    /// before any SAP bridge code runs. Idempotent across re-launches.
    static func start() {
        let fm = FileManager.default

        // 1. Archive the previous launch's currentLog → previousLog
        //    (remove any stale previousLog first so the move succeeds).
        try? fm.removeItem(at: previousLogURL)
        if fm.fileExists(atPath: currentLogURL.path) {
            try? fm.moveItem(at: currentLogURL, to: previousLogURL)
        }

        // 2. Truncate + redirect fd 2 (stderr) onto a fresh currentLog.
        //    `freopen` closes the old stderr and reopens the FILE* on the
        //    new path; it also dup2's the underlying fd onto fd 2, so
        //    Go's runtime — which writes via raw write(2) on fd 2 — also
        //    lands in the file.
        _ = freopen(currentLogURL.path, "w", stderr)

        // 3. If the previous launch left a non-empty log, dump its
        //    contents into AppLog so the user can see (via Share log)
        //    what killed the previous launch. The Go runtime's
        //    "fatal error: signal: SIGSEGV" + stack trace will be in
        //    here, which tells us exactly where Unicorn crashed.
        if let prevData = try? Data(contentsOf: previousLogURL),
           !prevData.isEmpty {
            let prev = String(data: prevData, encoding: .utf8) ?? "<binary>"
            AppLog.error("===== PREVIOUS LAUNCH STDERR (black-box recorder) =====", .app)
            // Split on newlines so each line is its own AppLog entry;
            // keeps the in-app log view readable and avoids any per-line
            // size limits in os.Logger.
            for line in prev.split(separator: "\n", omittingEmptySubsequences: false) {
                AppLog.error("  prev.stderr | " + String(line), .app)
            }
            AppLog.error("===== END PREVIOUS STDERR =====", .app)
        }

        startTailing()
    }

    /// Copies new stderr lines into AppLog while the app is running.
    ///
    /// Reading the log only on the next launch is what made the store smoke
    /// impossible to iterate on: relaunching to read it archives the current
    /// file over the previous one, so a launch that dies during pre-warm
    /// destroys the log of the run being investigated. Tailing the same file
    /// means the run can be read, and shared, while it is still in progress.
    static func startTailing() {
        tailOffset = 0

        let timer = DispatchSource.makeTimerSource(queue: tailQueue)
        timer.schedule(deadline: .now() + 1, repeating: 1)
        timer.setEventHandler { readNewLines() }
        timer.resume()

        tailTimer = timer
    }

    private static func readNewLines() {
        guard let handle = try? FileHandle(forReadingFrom: currentLogURL) else {
            return
        }

        defer { try? handle.close() }

        guard let end = try? handle.seekToEnd() else { return }

        // A relaunch truncates the file, so a smaller size means start over.
        if end < tailOffset {
            tailOffset = 0
        }

        guard end > tailOffset else { return }

        try? handle.seek(toOffset: tailOffset)

        let length = Int(end - tailOffset)
        let data = (try? handle.read(upToCount: length)) ?? Data()

        tailOffset = end

        guard !data.isEmpty, let text = String(data: data, encoding: .utf8) else {
            return
        }

        for line in text.split(separator: "\n", omittingEmptySubsequences: true) {
            AppLog.info(String(line), .sap)
        }
    }

    private static let tailQueue = DispatchQueue(label: "com.a23bc.dliparebuild.stderr-tail")
    private static var tailTimer: DispatchSourceTimer?
    private static var tailOffset: UInt64 = 0
}
