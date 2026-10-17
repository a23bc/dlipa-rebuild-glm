package sap

import (
        "fmt"
        "os"
        "runtime"
)

// reportRSS prints the process's current resident size and the Go runtime's
// heap stats to stderr. On iOS there is no /proc/self/status; we use the
// mach task_self system call via libc (task_info with TASK_BASIC_INFO),
// which gives resident_size in bytes.
//
// Why this exists: the SAP bridge mmaps ~160 MB across many Unicorn
// uc_mem_map calls (CoreFP 95MB + AppleMediaServices 15MB + scratch
// 16MB + heap 32MB + stack 4MB). iOS applies a per-process memory
// ceiling — crossing it triggers Memorystatus (jetsam), which SIGKILLs
// the process with no crash report and no chance for our deferred
// recover() to run. We saw exactly this: StderrCapture recorded
// "[SAP] initializing guest..." as the last stderr line and nothing
// after — the process was killed mid-call, no fatal error, no panic.
//
// Reporting RSS at each step lets the device log show the actual
// memory trajectory, so we can confirm jetsam is the cause and tune
// the memory layout accordingly.
//
// On iOS we link libc directly via purego (no cgo for the symbol
// lookup). On macOS/Linux we fall back to reading /proc or vmmap.
//
// `step` is a label like "before initialize" / "after initialize".
func reportRSS(step string) {
        var m runtime.MemStats
        runtime.ReadMemStats(&m)

        // Try mach task_info first (iOS + macOS).
        rss := rssBytesMach()
        if rss == 0 {
                rss = rssBytesProcFS()
        }

        fmt.Fprintf(os.Stderr, "[SAP] rss %s: go_heap=%d go_sys=%d rss=%d\n",
                step, m.HeapAlloc, m.Sys, rss)
}
