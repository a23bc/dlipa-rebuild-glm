//go:build !darwin

package sap

import (
	"os"
	"strconv"
	"strings"
)

// rssBytesMach is a no-op on non-Darwin; rssBytesProcFS handles Linux.
func rssBytesMach() uint64 { return 0 }

// rssBytesProcFS reads /proc/self/statm (Linux) or returns 0.
// statm field 2 (resident) is in pages; multiply by os.Getpagesize().
func rssBytesProcFS() uint64 {
	data, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) < 2 {
		return 0
	}
	pages, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0
	}
	return pages * uint64(os.Getpagesize())
}
