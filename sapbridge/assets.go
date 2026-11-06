package sapbridge

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/a23bc/dlipa-rebuild/sapbridge/internal/sap/assets"
	"github.com/a23bc/dlipa-rebuild/sapbridge/internal/sap/assetsremote"
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
	bundle, err := assets.Load(ctx)
	cancel()
	if err == nil {
		bundleCache = &bundle
		bundleCached = dir
		return bundle, nil
	}

	// Nothing staged and nothing cached. Resolve the profile from Apple's pinned
	// restore image: the extractor checks size and SHA-256 before it writes, so
	// the cache ends up holding exactly the bytes the digests describe, or
	// nothing. A phone measured this at 211.7 MiB over 457 range requests in
	// 52 seconds, which is why it gets its own generous context -- the 30 second
	// budget above is for reading a local copy, not for a download.
	fmt.Fprintf(os.Stderr,
		"sap assets: not cached (%v); resolving from Apple, about 212 MB\n", err)

	fetchCtx, cancelFetch := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancelFetch()
	if _, fetchErr := assetsremote.Load(fetchCtx); fetchErr != nil {
		return assets.Bundle{}, fmt.Errorf(
			"fetch Apple SAP assets after a cache miss (%v): %w", err, fetchErr)
	}

	// Read the result back through the caching loader instead of memoising what
	// the extractor returned: that one is the fat 125 MB image, and a handshake
	// already leaves the process near 215 MB resident. Holding both is the copy
	// that jetsam used to kill silently between the handshake and the next step;
	// readCache hands back the arm64 slices the engine actually maps.
	readCtx, cancelRead := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelRead()

	bundle, err = assets.Load(readCtx)
	if err != nil {
		return assets.Bundle{}, fmt.Errorf("read the fetched SAP asset cache: %w", err)
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

	// Sliced after validation, not before: the digest is the whole file's, and the
	// engine only ever reads the arm64 slice. CoreFP is 95 MB, 31 MB of which are
	// used -- and the open that follows is where memory runs out.
	coreFP, err = assets.SliceArm64(coreFP)
	if err != nil {
		return assets.Bundle{}, fmt.Errorf("slice CoreFP: %w", err)
	}

	appleMediaServices, err = assets.SliceArm64(appleMediaServices)
	if err != nil {
		return assets.Bundle{}, fmt.Errorf("slice AppleMediaServices: %w", err)
	}

	commerce, err = assets.SliceArm64(commerce)
	if err != nil {
		return assets.Bundle{}, fmt.Errorf("slice commerce: %w", err)
	}

	return assets.Bundle{
		AppleMediaServices: appleMediaServices,
		Commerce:           commerce,
		CoreFP:             coreFP,
		CoreFPICXS:         coreFPICXS,
	}, nil
}
