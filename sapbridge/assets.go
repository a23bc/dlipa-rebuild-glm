package sapbridge

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/a23bc/dlipa-rebuild/sapbridge/internal/sap/assets"
)

// BundleDir is where the app looks for the four Apple binaries. The iOS app
// copies them out of its own bundle into Library/Caches on first launch,
// because the upstream loader uses os.UserCacheDir().
var BundleDir string

// The bundle is ~125 MB and never changes once written, but every load reads it
// into fresh memory. Signing and kbsync are two separate entry points that each
// want it, and loading it twice costs a second 125 MB.
//
// That is not a theoretical waste on iOS. A handshake leaves the process around
// 215 MB resident; the second copy took it past the per-process ceiling and
// jetsam killed it between "handshake complete!" and the next step, leaving no
// stderr line and no crash report. One copy, shared by every caller, is the
// difference between fitting and not fitting.
var (
	bundleMu     sync.Mutex
	bundleCache  *assets.Bundle
	bundleCached string
)

// invalidateBundleCache drops the memoised bundle. Called when the directory
// changes, because a bundle from the old path would be the wrong bytes.
func invalidateBundleCache() {
	bundleMu.Lock()
	bundleCache = nil
	bundleCached = ""
	bundleMu.Unlock()
}

// loadBundle resolves the pinned Apple SAP asset profile, reading it at most
// once per configured directory.
//
// It returns an error rather than panicking, so a machine without the assets
// (CI, a fresh install) gets a clear message instead of a crash.
func loadBundle() (assets.Bundle, error) {
	dir := BundleDir
	if dir == "" {
		dir = bundleDir
	}

	bundleMu.Lock()
	defer bundleMu.Unlock()

	if bundleCache != nil && bundleCached == dir {
		return *bundleCache, nil
	}

	if dir != "" {
		bundle, err := readBundleDir(dir)
		if err != nil {
			return assets.Bundle{}, err
		}
		bundleCache = &bundle
		bundleCached = dir
		return bundle, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	bundle, err := assets.Load(ctx)
	if err != nil {
		msg := "Apple SAP assets are not present in the cache directory; "
		msg += "copy the four pinned binaries there or call SetBundleDir: "
		return assets.Bundle{}, fmt.Errorf("%s%w", msg, err)
	}

	bundleCache = &bundle
	bundleCached = dir
	return bundle, nil
}

// readBundleDir loads the four pinned binaries from an explicit directory.
func readBundleDir(dir string) (assets.Bundle, error) {
	read := func(name string) ([]byte, error) {
		return readFile(dir + "/" + name)
	}

	appleMediaServices, err := read("AppleMediaServices")
	if err != nil {
		return assets.Bundle{}, fmt.Errorf("read AppleMediaServices: %w", err)
	}

	commerce, err := read("commerce")
	if err != nil {
		return assets.Bundle{}, fmt.Errorf("read commerce: %w", err)
	}

	coreFP, err := read("CoreFP")
	if err != nil {
		return assets.Bundle{}, fmt.Errorf("read CoreFP: %w", err)
	}

	coreFPICXS, err := read("CoreFP.icxs")
	if err != nil {
		return assets.Bundle{}, fmt.Errorf("read CoreFP.icxs: %w", err)
	}

	bundle := assets.Bundle{
		AppleMediaServices: appleMediaServices,
		Commerce:           commerce,
		CoreFP:             coreFP,
		CoreFPICXS:         coreFPICXS,
	}

	// Reuse the upstream validator so a truncated or tampered file is caught
	// here, where the error can name what is wrong.
	if err := assets.Validate(bundle); err != nil {
		return assets.Bundle{}, err
	}

	return bundle, nil
}
