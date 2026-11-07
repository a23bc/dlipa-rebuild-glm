import Foundation
import OSLog

/// In-app and system logging.
///
/// print() is invisible on a real device: it writes to stdout, which nothing
/// reads once the app is not attached to a debugger. Everything here goes through
/// os.Logger, so messages appear in Console.app and in
/// `log stream --predicate 'subsystem == "com.a23bc.dliparebuild"'`.
///
/// Each message is also kept in a bounded in-app buffer the UI can display,
/// because attaching a device to Console is not something a user wants to do.
enum AppLog {

    static let subsystem = "com.a23bc.dliparebuild"

    private static let store = LogStore()

    enum Category: String, CaseIterable {
        case app = "app"
        case auth = "auth"
        case sap = "sap"
        case assets = "assets"
        case network = "network"
        case download = "download"

        var logger: Logger {
            Logger(subsystem: AppLog.subsystem, category: rawValue)
        }
    }

    enum Level: Int, Comparable, CaseIterable {
        case debug = 0
        case info = 1
        case warn = 2
        case error = 3

        static func < (lhs: Level, rhs: Level) -> Bool { lhs.rawValue < rhs.rawValue }

        var label: String {
            switch self {
            case .debug: return "DEBUG"
            case .info: return "INFO"
            case .warn: return "WARN"
            case .error: return "ERROR"
            }
        }
    }

    /// Where the switch in Diagnostics stores its state.
    static let recordingKey = "com.a23bc.dliparebuild.recordLog"

    /// The level a build starts at, before the recording switch is considered.
    private static var releaseLevel: Level {
        #if DEBUG
        return .debug
        #else
        return .info
        #endif
    }

    /// What reaches the buffer and the system log.
    static var minimumLevel: Level = UserDefaults.standard.bool(forKey: recordingKey)
        ? .debug
        : AppLog.releaseLevel

    /// When on, every level is kept, including the debug lines that describe a
    /// request and its response.
    ///
    /// Release builds start at .info, so the useful detail is dropped before
    /// anyone can read it. This is the switch that makes a device log worth
    /// sending: turn it on, reproduce the failure, share the log.
    static var isRecording: Bool {
        get { minimumLevel == .debug }
        set {
            UserDefaults.standard.set(newValue, forKey: recordingKey)
            minimumLevel = newValue ? .debug : AppLog.releaseLevel
        }
    }

    static func debug(_ message: @autoclosure @escaping () -> String,
                     _ category: Category = .app,
                     file: String = #file, function: String = #function, line: UInt = #line) {
        log(.debug, message(), category, file: file, function: function, line: line)
    }

    static func info(_ message: @autoclosure @escaping () -> String,
                    _ category: Category = .app,
                    file: String = #file, function: String = #function, line: UInt = #line) {
        log(.info, message(), category, file: file, function: function, line: line)
    }

    static func warn(_ message: @autoclosure @escaping () -> String,
                    _ category: Category = .app,
                    file: String = #file, function: String = #function, line: UInt = #line) {
        log(.warn, message(), category, file: file, function: function, line: line)
    }

    static func error(_ message: @autoclosure @escaping () -> String,
                     _ category: Category = .app,
                     file: String = #file, function: String = #function, line: UInt = #line) {
        log(.error, message(), category, file: file, function: function, line: line)
    }

    private static func log(_ level: Level, _ message: String, _ category: Category,
                            file: String, function: String, line: UInt) {
        guard level >= minimumLevel else { return }

        let name = (file as NSString).lastPathComponent
        let entry = LogEntry(timestamp: Date(), level: level, category: category,
                             message: message, source: name + ":" + String(line))

        // The switch is labelled "Record log", so off has to mean the in-app
        // buffer stays empty. Raising the level alone still recorded everything
        // at .info and up, which is exactly what the switch appeared not to do.
        // os_log still receives the line either way: Console.app does not need
        // this switch, the share-it-from-the-phone flow does.
        if isRecording {
            store.append(entry)
        }

        // os.Logger takes a format string, so a literal percent sign has to be
        // escaped or the message is truncated at the first one.
        let safe = message.replacingOccurrences(of: "%", with: "%%")
        let full = entry.source + " | " + safe

        switch level {
        case .debug: category.logger.debug("\(full)")
        case .info: category.logger.info("\(full)")
        case .warn: category.logger.warning("\(full)")
        case .error: category.logger.error("\(full)")
        }
    }

    static var entries: [LogEntry] { store.entries }

    /// How many lines the window holds, for a view that shows a tail of it and
    /// has to say how much it left out.
    static var lineCount: Int { store.count }

    static func tail(_ count: Int) -> [LogEntry] { store.tail(count) }

    /// Calls the handler on the main thread when the buffer changes, at most
    /// once per turn. It carries no payload on purpose: a viewer that wants the
    /// window reads the tail of it, and a viewer that wants everything exports
    /// it, which is a button and not a per-line cost.
    static func onChanged(_ handler: (() -> Void)?) {
        store.onChange = handler
    }

    static func clear() { store.clear() }

    /// Exports the buffer so a user can send a log back without a cable.
    static func exportText() -> String {
        store.entries.map { $0.plainText }.joined(separator: "\n")
    }
}

struct LogEntry: Identifiable {
    let id = UUID()
    let timestamp: Date
    let level: AppLog.Level
    let category: AppLog.Category
    let message: String
    let source: String

    /// One formatter for the process, never mutated after this.
    ///
    /// Built per line before: a log tail of four hundred entries allocated four
    /// hundred of them, and the tail is the thing that runs when the app is
    /// already busy -- so the reporter paid for the burst it was reporting. An
    /// immutable formatter is shareable, and nothing here sets options or a
    /// calendar on it.
    private static let stamp: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        return formatter
    }()

    var plainText: String {
        let stamp = LogEntry.stamp.string(from: timestamp)
        return stamp + " " + level.label + "/" + category.rawValue + " " + message
    }
}

/// Bounded buffer: a long session can grow without unbounded memory use.
private final class LogStore {
    private let queue = DispatchQueue(label: "com.a23bc.dliparebuild.log")
    private var buffer: [LogEntry] = []
    // The store smoke writes a hundred lines of its own, and the live stderr
    // tail adds them as it goes. 500 pushed the first half out of the window
    // before the run had finished.
    private let limit = 4000

    var onChange: (() -> Void)?

    // Whether a notification is already waiting on the main thread. Read and
    // written only on the queue above, so the reset arrives back through it.
    private var notifying = false

    var entries: [LogEntry] {
        queue.sync { buffer }
    }

    var count: Int {
        queue.sync { buffer.count }
    }

    /// The last `count` entries, copied without the rest of the window.
    func tail(_ count: Int) -> [LogEntry] {
        queue.sync { Array(buffer.suffix(count)) }
    }

    func append(_ entry: LogEntry) {
        queue.async {
            self.buffer.append(entry)
            if self.buffer.count > self.limit {
                self.buffer.removeFirst(self.buffer.count - self.limit)
            }

            // One notification per turn of the main thread, whatever that turn
            // produced. Copying the window and hopping to main for every line
            // made each line cost what the whole window costs, and the writers
            // that matter are the bursty ones: a store-runtime open reports over
            // a hundred lines inside a second, and a version list reports several
            // hundred. The screen that showed them was the thing that stopped
            // responding while the thing it reported on was running.
            guard !self.notifying else { return }
            self.notifying = true

            DispatchQueue.main.async {
                self.onChange?()
                self.queue.async { self.notifying = false }
            }
        }
    }

    func clear() {
        queue.async {
            self.buffer.removeAll()

            DispatchQueue.main.async {
                self.onChange?()
            }
        }
    }
}
