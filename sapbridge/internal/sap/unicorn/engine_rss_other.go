//go:build !darwin

package unicorn

// maxResidentMB is only reported on the platforms the app ships to; the host
// build has no cheap equivalent and nothing to diagnose.
func maxResidentMB() uint64 { return 0 }
