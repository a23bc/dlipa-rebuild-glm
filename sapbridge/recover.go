package sapbridge

import (
        "fmt"
        "runtime/debug"
)

// recoverPanic converts a Go panic into an error. It MUST be invoked as a
// deferred function: `defer func() { rec := recoverPanic("name"); if rec != nil { err = rec } }()`.
//
// gomobile does not install a recover() at the Go↔ObjC boundary. Any panic
// that escapes a gomobile-exported function is handled by the Go runtime,
// which prints a stack trace to stderr and calls os.Exit(2). On iOS this
// kills the host process — no crash report, just atexit handlers firing
// (which is exactly what we observed in syslog: "Entering exit handler"
// immediately after the second SAP exchange). The app vanishes from the
// user's perspective with no diagnostic.
//
// Wrapping each exported entry point with this helper turns the panic into
// an error that gomobile marshals back to Swift as an NSError. The caller
// (SAPSigner.swift) then logs the panic value + stack via AppLog.error,
// which surfaces in (a) the in-app log view and shareable log, and (b)
// the system log via OSLog. The next sign-in attempt will produce a
// useful diagnostic instead of a silent process death.
func recoverPanic(where string) error {
        r := recover()
        if r == nil {
                return nil
        }

        // Capture up to 32 KB of stack trace so we can see where the panic
        // originated. debug.Stack() returns the goroutine's full stack,
        // which on iOS can be large; the cap keeps it manageable.
        stack := debug.Stack()
        if len(stack) > 32*1024 {
                stack = stack[:32*1024]
        }

        return fmt.Errorf("Go panic in %s: %v\n--- stack ---\n%s", where, r, stack)
}

// runRecovered invokes fn and converts any panic into an error. This is
// the synchronous form for entry points that want recover semantics
// without managing their own defer.
//
// Usage:
//
//      err := runRecovered("SAP handshake", func() error {
//          return heavyWork()
//      })
func runRecovered(where string, fn func() error) (err error) {
        defer func() {
                if rec := recoverPanic(where); rec != nil {
                        err = rec
                }
        }()
        return fn()
}
