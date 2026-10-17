//go:build !ios

package unicorn

// ForceLink is a no-op everywhere except the ios build, where link_force.go
// provides the real implementation. On the desktop hosts Unicorn comes from a
// shared library or is unavailable, and the macOS test build has no static
// archive to force into the link.
func ForceLink() {}
