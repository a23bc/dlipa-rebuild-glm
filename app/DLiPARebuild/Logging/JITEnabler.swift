import Foundation
import Darwin

/// Attempts to enable JIT by calling ptrace(PT_TRACE_ME).
///
/// On iOS, anonymous mmap with PROT_EXEC "succeeds" (returns a valid
/// pointer) but the kernel silently refuses to set the hardware-level
/// execute permission bit in the arm64 page table. When the CPU tries
/// to execute code from such a page, it raises SIGBUS.
///
/// The only way to make the kernel actually set the execute bit is to
/// have the CS_DEBUGGED flag on the process. This flag is normally set
/// when a debugger attaches via ptrace(PT_ATTACH). But PT_TRACE_ME —
/// a process tracing itself — also sets CS_DEBUGGED, and as a side
/// effect it disables code signing validation entirely.
///
/// This technique was described by Saagar Jha in "Jailed Just-in-Time
/// Compilation on iOS" (2020). It worked on iOS 13-14. Apple may have
/// blocked it in later versions, but it's worth trying with TrollStore
/// since TrollStore already bypasses many security checks.
///
/// We call this at app launch, before any Unicorn code runs. If it
/// fails (returns -1), we log the error but continue — the app will
/// still work for non-JIT operations, and the SAP bridge will just
/// SIGBUS as before.
enum JITEnabler {
    static func enable() {
        // PT_TRACE_ME = 0 (from sys/ptrace.h)
        // ptrace(PT_TRACE_ME, 0, 0, 0) — trace self, no pid, no addr, no data
        let result = ptrace(0, 0, nil, 0)
        if result == 0 {
            AppLog.info("ptrace(PT_TRACE_ME) succeeded — CS_DEBUGGED set, JIT should work", .app)
        } else {
            let errno_str = String(cString: strerror(errno))
            AppLog.error("ptrace(PT_TRACE_ME) failed: errno=\(errno) (\(errno_str))", .app)
            fputs("[DLiPA] ptrace(PT_TRACE_ME) failed: errno=\(errno) (\(errno_str))\n", stderr)
        }
    }
}
