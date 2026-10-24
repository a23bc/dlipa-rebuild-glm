package machine

import (
	"sort"
	"sync"
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
)

// recordExternalCall used to be called from the service dispatcher on every
// external symbol the guest entered. That is the hottest path in an interpreted
// guest, and the mutex plus map write cost was paid on every call long after the
// question it answered had been settled.
//
// It is kept, and still wired into the callreport test, but nothing on the
// production path calls it any more.
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
