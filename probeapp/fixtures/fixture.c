// A deliberately trivial dylib, built four ways (two platforms x two fixup
// eras) and dlopen'd on the device.
//
// The point is not what it does. The point is to find out what iOS 15's dyld
// will accept before we spend the effort converting the 119 MB of real Apple
// binaries. A 1 KB answer beats a week of guesswork.
//
// No includes: this compiles against both the iOS and the macOS SDK, and any
// system header would drag in the wrong platform's declarations.
int probe_fixture_value(void) {
	return 42;
}
