import Foundation
import Darwin

/// At this point we've exhausted all approaches for executing
/// external code on iOS 15 non-jailbreak:
/// - mmap(PROT_EXEC) = EPERM
/// - dlopen = "unknown imports format" (chained fixups not supported)
/// - ptrace(PT_TRACE_ME) = EPERM
/// - Unicorn JIT = SIGBUS (anonymous PROT_EXEC not allowed)
///
/// The only remaining path: link commerce code into the app's own
/// __TEXT segment at compile time. Then no runtime PROT_EXEC is
/// needed — the code is in the main executable, which iOS always
/// allows to execute.
///
/// This test just verifies the commerce_native file is accessible
/// in the bundle so we can read its Mach-O data for linking.
enum ExecTest {
    static func testBundleFileExec() {
        guard let url = Bundle.main.url(forResource: "commerce_native", withExtension: nil) else {
            AppLog.error("ExecTest: commerce_native not found in bundle", .app)
            return
        }

        let path = url.path
        AppLog.info("ExecTest: commerce_native found at \(path)", .app)

        // Read file size
        if let attrs = try? FileManager.default.attributesOfItem(atPath: path),
           let size = attrs[.size] as? Int {
            AppLog.info("ExecTest: file size = \(size) bytes", .app)
        }

        // Read first 4 bytes (Mach-O magic)
        if let fh = FileHandle(forReadingAtPath: path) {
            let magic = fh.readData(ofLength: 4)
            let magicHex = magic.map { String(format: "%02x", $0) }.joined(separator: " ")
            AppLog.info("ExecTest: Mach-O magic: \(magicHex)", .app)
            fputs("[DLiPA] ExecTest: commerce_native magic=\(magicHex)\n", stderr)
            fh.closeFile()
        }
    }
}
