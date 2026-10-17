package sapbridge

import (
	"context"
	"fmt"
	"time"

	"github.com/a23bc/dlipa-rebuild/sapbridge/internal/sap/assets"
)

// BundleDir is where the app looks for the four Apple binaries. The iOS app
// copies them out of its own bundle into Library/Caches on first launch,
// because the upstream loader uses os.UserCacheDir().
var BundleDir string

// loadBundle resolves the pinned Apple SAP asset profile.
//
// It returns an error rather than panicking, so a machine without the assets
// (CI, a fresh install) gets a clear message instead of a crash.
func loadBundle() (assets.Bundle, error) {
	dir := BundleDir
	if dir == "" {
		dir = bundleDir
	}
	if dir != "" {
		return readBundleDir(dir)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	bundle, err := assets.Load(ctx)
	if err != nil {
		msg := "Apple SAP assets are not present in the cache directory; "
		msg += "copy the four pinned binaries there or call SetBundleDir: "
		return assets.Bundle{}, fmt.Errorf("%s%w", msg, err)
	}
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
