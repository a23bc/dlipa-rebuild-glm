//go:build darwin

package unicorn

import "syscall"

// maxResidentMB is the high-water resident size of this process, in MiB.
//
// Getrusage is the only figure available from a c-archive without cgo-side
// plumbing, and a high-water mark is what matters: the allocation that fails is
// asked for when the process is at its largest.
func maxResidentMB() uint64 {
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		return 0
	}

	// Darwin reports Maxrss in bytes.
	return uint64(usage.Maxrss) / (1 << 20)
}
