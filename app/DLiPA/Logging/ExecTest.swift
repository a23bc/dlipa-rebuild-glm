import Foundation
import Darwin

/// Tests whether iOS allows mmap with PROT_EXEC on a code-signed file
/// in the app bundle. This is the fundamental requirement for the
/// native execution approach (replacing Unicorn).
///
/// If this test passes, we can mmap the stripped commerce binary with
/// PROT_EXEC and execute its ARM64 code natively — no Unicorn, no JIT,
/// no anonymous executable memory needed.
///
/// If this test fails, the native execution approach won't work on
/// this device/iOS version, and we need a different strategy.
enum ExecTest {
    static func testBundleFileExec() {
        guard let url = Bundle.main.url(forResource: "commerce_native", withExtension: nil) else {
            AppLog.error("ExecTest: commerce_native not found in bundle", .app)
            return
        }

        let path = url.path
        AppLog.info("ExecTest: testing mmap(PROT_EXEC) on \(path)", .app)

        // Open the file
        let fd = open(path, O_RDONLY)
        guard fd >= 0 else {
            AppLog.error("ExecTest: open failed: errno=\(errno) (\(String(cString: strerror(errno))))", .app)
            return
        }
        defer { close(fd) }

        // Get file size
        var st = stat()
        guard fstat(fd, &st) == 0 else {
            AppLog.error("ExecTest: fstat failed: errno=\(errno)", .app)
            return
        }
        let size = Int(st.st_size)
        AppLog.info("ExecTest: file size = \(size) bytes", .app)

        // Try mmap with PROT_READ | PROT_EXEC
        let ptr = mmap(nil, size, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0)
        if ptr == MAP_FAILED || ptr == nil {
            let err = errno
            AppLog.error("ExecTest: mmap(PROT_READ|PROT_EXEC) FAILED: errno=\(err) (\(String(cString: strerror(err))))", .app)
            fputs("[DLiPA] ExecTest: mmap PROT_EXEC failed: errno=\(err) (\(String(cString: strerror(err))))\n", stderr)

            // Also try PROT_READ only (control test)
            let ptr2 = mmap(nil, size, PROT_READ, MAP_PRIVATE, fd, 0)
            if ptr2 == MAP_FAILED || ptr2 == nil {
                AppLog.error("ExecTest: mmap(PROT_READ) also failed — file unreadable", .app)
            } else {
                AppLog.info("ExecTest: mmap(PROT_READ) succeeded — file is readable but not executable", .app)
                munmap(ptr2, size)
            }
            return
        }

        // Success! We have executable memory.
        // Read the first 4 bytes (should be Mach-O magic 0xfeedfacf)
        let magic = ptr!.withMemoryRebound(to: UInt32.self, capacity: 1) { $0.pointee }
        AppLog.info("ExecTest: mmap(PROT_EXEC) SUCCEEDED! ptr=\(String(format: "%p", ptr!)) magic=0x\(String(magic, radix: 16))", .app)
        fputs("[DLiPA] ExecTest: mmap PROT_EXEC SUCCEEDED! magic=0x\(String(magic, radix: 16))\n", stderr)

        // Try to read a few instruction bytes (just to verify we can access the memory)
        let bytes = ptr!.withMemoryRebound(to: UInt8.self, capacity: 4) { p -> [UInt8] in
            return [p[0], p[1], p[2], p[3]]
        }
        AppLog.info("ExecTest: first 4 bytes: \(bytes.map { String(format: "%02x", $0) }.joined(separator: " "))", .app)

        // Don't munmap — we might use this memory later
        // munmap(ptr, size)
    }
}
