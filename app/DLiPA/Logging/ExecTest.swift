import Foundation
import Darwin

/// Tests whether iOS allows dlopen() on a code-signed dylib in the
/// app bundle. This is the fundamental requirement for the native
/// execution approach.
///
/// iOS forbids mmap(PROT_EXEC) on files (EPERM). But dyld can load
/// signed dylibs. With the com.apple.security.cs.disable-library-
/// validation entitlement, third-party (non-Apple) dylibs can be
/// loaded. dlopen goes through dyld, not mmap, so it bypasses the
/// PROT_EXEC restriction.
///
/// If this test passes, we can load the stripped commerce binary as
/// a dylib and execute its ARM64 code natively via function pointers.
enum ExecTest {
    static func testBundleFileExec() {
        // Try dlopen on commerce.dylib
        guard let url = Bundle.main.url(forResource: "commerce", withExtension: "dylib") else {
            AppLog.error("ExecTest: commerce.dylib not found in bundle", .app)
            // Also check if it's in a Frameworks/ subdirectory
            let frameworksPath = Bundle.main.bundlePath + "/Frameworks/commerce.dylib"
            if FileManager.default.fileExists(atPath: frameworksPath) {
                AppLog.info("ExecTest: found at \(frameworksPath), trying dlopen", .app)
                testDlopen(frameworksPath)
            }
            return
        }
        testDlopen(url.path)
    }

    static func testDlopen(_ path: String) {
        AppLog.info("ExecTest: testing dlopen on \(path)", .app)
        fputs("[DLiPA] ExecTest: testing dlopen on \(path)\n", stderr)

        // Try dlopen
        let handle = dlopen(path, RTLD_NOW | RTLD_LOCAL)
        if handle == nil {
            let err = String(cString: dlerror())
            AppLog.error("ExecTest: dlopen FAILED: \(err)", .app)
            fputs("[DLiPA] ExecTest: dlopen FAILED: \(err)\n", stderr)

            // Also try RTLD_LAZY
            let handle2 = dlopen(path, RTLD_LAZY | RTLD_LOCAL)
            if handle2 != nil {
                AppLog.info("ExecTest: dlopen(RTLD_LAZY) SUCCEEDED!", .app)
                fputs("[DLiPA] ExecTest: dlopen(RTLD_LAZY) SUCCEEDED!\n", stderr)
                dlclose(handle2)
            }
            return
        }

        AppLog.info("ExecTest: dlopen SUCCEEDED! handle=\(String(describing: handle))", .app)
        fputs("[DLiPA] ExecTest: dlopen SUCCEEDED!\n", stderr)

        // Try to find a symbol (any symbol — just to verify we can
        // call code from the dylib)
        // The commerce binary has no standard exports, so we just
        // verify dlopen succeeded. Actual symbol resolution will
        // happen when we implement the native execution layer.

        dlclose(handle)
    }
}
