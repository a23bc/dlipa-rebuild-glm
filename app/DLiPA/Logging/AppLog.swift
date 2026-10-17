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

    static var minimumLevel: Level = {
        #if DEBUG
        return .debug
        #else
        return .info
        #endif
    }()

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
        store.append(entry)

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

    static func onUpdate(_ handler: @escaping ([LogEntry]) -> Void) {
        store.onUpdate = handler
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

    var plainText: String {
        let stamp = ISO8601DateFormatter().string(from: timestamp)
        return stamp + " " + level.label + "/" + category.rawValue + " " + message
    }
}

/// Bounded buffer: a long session can grow without unbounded memory use.
private final class LogStore {
    private let queue = DispatchQueue(label: "com.a23bc.dliparebuild.log")
    private var buffer: [LogEntry] = []
    private let limit = 500

    var onUpdate: (([LogEntry]) -> Void)?

    var entries: [LogEntry] {
        queue.sync { buffer }
    }

    func append(_ entry: LogEntry) {
        queue.async {
            self.buffer.append(entry)
            if self.buffer.count > self.limit {
                self.buffer.removeFirst(self.buffer.count - self.limit)
            }
            let snapshot = self.buffer
            DispatchQueue.main.async {
                self.onUpdate?(snapshot)
            }
        }
    }

    func clear() {
        queue.async {
            self.buffer.removeAll()
            DispatchQueue.main.async {
                self.onUpdate?([])
            }
        }
    }
}
