package sapbridge

// bundleDir is where the app has staged the four Apple SAP binaries. It is set
// once from the iOS app and takes precedence over BundleDir.
var bundleDir string

// SetBundleDir records where the four Apple SAP binaries live.
//
// The iOS app copies them out of its read-only bundle on first launch and calls
// this once.
func SetBundleDir(path string) {
	bundleDir = path
	invalidateBundleCache()
}

// BundleDirValue returns the directory currently configured, or "" if unset.
func BundleDirValue() string {
	if BundleDir != "" {
		return BundleDir
	}
	return bundleDir
}
