package machine

import (
	"sort"
	"sync"
	"sync/atomic"
)

// ExternalCall is one external symbol the guest actually entered, with the
// number of times it did so.
type ExternalCall struct {
	Name  string
	Count uint64
}

var (
	externalCallsMu sync.Mutex
	externalCalls   = map[string]uint64{}

	// countShimCalls decides whether the dispatcher records anything. Recording
	// is a mutex and a map write on the hottest path in an interpreted guest, and
	// it was removed from that path once the question it answered had been
	// answered -- which left the reader side intact and the report permanently
	// zero, silently. So the write is back, and it happens only while something
	// asks for it.
	countShimCalls atomic.Bool
)

// SetCallCounting turns the dispatcher's recording on or off and reports the
// previous value, so a caller restores what it found instead of assuming it was
// off.
//
// The counts are process-wide, not per machine, which is what lets one caller
// attribute them to one operation with ResetExternalCalls while another is
// measuring a whole test.
func SetCallCounting(on bool) bool { return countShimCalls.Swap(on) }

// CallCounting reports the current setting.
func CallCounting() bool { return countShimCalls.Load() }

// recordExternalCall is the write side of the report, called from the service
// dispatcher while SetCallCounting is on.
func recordExternalCall(name string) {
	externalCallsMu.Lock()
	defer externalCallsMu.Unlock()

	externalCalls[name]++
}

// ExternalCalls reports every external symbol the guest has entered since the
// last reset, most-called first.
//
// This exists to size the dlopen path. The static import tables say the pinned
// binaries declare 196, 976 and 289 external symbols, but a declaration is not
// a call: almost none of them are ever reached. Under dlopen the difference is
// decisive. A dependency listed in LC_LOAD_DYLIB must exist at load time
// whether or not its symbols are used, but a weakly linked one that is
// actually called becomes a NULL function pointer and crashes. So the number
// that decides whether dlopen is a small job or an impossible one is how many
// symbols the SAP path really enters, and that is exactly what this reports.
func ExternalCalls() []ExternalCall {
	externalCallsMu.Lock()
	defer externalCallsMu.Unlock()

	out := make([]ExternalCall, 0, len(externalCalls))
	for name, count := range externalCalls {
		out = append(out, ExternalCall{Name: name, Count: count})
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}

		return out[i].Name < out[j].Name
	})

	return out
}

// ResetExternalCalls clears the counts, so a caller can attribute them to one
// specific operation.
func ResetExternalCalls() {
	externalCallsMu.Lock()
	defer externalCallsMu.Unlock()

	externalCalls = map[string]uint64{}
}
