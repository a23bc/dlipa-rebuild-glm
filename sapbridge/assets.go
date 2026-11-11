package sapbridge

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/a23bc/dlipa-rebuild/sapbridge/internal/sap/assets"
	"github.com/a23bc/dlipa-rebuild/sapbridge/internal/sap/assetsremote"
)

// BundleDir is where the app looks for the four Apple binaries. The iOS app
// copies them out of its own bundle into Library/Caches on first launch,
// because the upstream loader uses os.UserCacheDir().
var BundleDir string

// allowedAssetFetch is the app's permission to spend about 212 MB of someone's
// data plan on the four Apple binaries. It starts closed: the bridge never
// decides that on its own, and the app opens it the moment a person answers
// yes -- which is the only moment anything here can claim they did.
//
// There is no way to close it again on purpose. Revoking consent mid-session
// has no meaning for a download that is already paid for, and an interface
// without a bool parameter is also an interface whose ObjC mapping nobody has
// to guess at: gomobile's own header renders a bool *return* as BOOL, and no
// caller here needs to test what it does with a bool argument.
var allowedAssetFetch atomic.Bool

// AllowAssetFetch opens the network fallback in loadBundle.
func AllowAssetFetch() {
	allowedAssetFetch.Store(true)
}

// AssetFetchAllowed reports the current answer, for the screen deciding whether
// to ask again after a fetch that was allowed and still failed.
func AssetFetchAllowed() bool {
	return allowedAssetFetch.Load()
}

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
	//
	// That much data is someone's mobile plan, so it happens only after the app
	// has asked and been told yes. Nothing here can promise the person was
	// asked: newSigner loads the bundle, so creating a signer reaches this line,
	// and a gate that only the download path honoured could be walked past by a
	// sign-in.
	if !allowedAssetFetch.Load() {
		return assets.Bundle{}, fmt.Errorf(
			"apple SAP assets are not on this device (%v), and the fetch is not "+
				"allowed yet: the app has to ask first", err)
	}

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

// AssetsCached reports whether the four Apple binaries are already on this
// device, in the cache the loader writes.
//
// The app asks before it offers to fetch them. It only needs to ask when there
// is a fetch to make: the download costs about 212 MB once, and after that the
// answer is on disk, so asking again would be a false alarm about someone else
// data plan.
func AssetsCached() bool {
	return assets.Cached()
}

// appleMediaServicesImage returns the AppleMediaServices bytes the store
// runtime signs with.
//
// It reads a file rather than the memoised bundle on purpose: on device the
// bundle handed to a call was empty even though the same loader, called during
// pre-warm, had the real bytes, so the file is the only source observed correct
// at both moments.
func appleMediaServicesImage() ([]byte, error) {
	path, err := appleMediaServicesPath()
	if err != nil {
		return nil, err
	}

	image, err := readFile(path)
	if err != nil {
		return nil, fmt.Errorf("sapbridge: read %s: %w", path, err)
	}

	return image, nil
}

// appleMediaServicesPath names the file appleMediaServicesImage reads.
//
// An app that ships the binaries stages them and sets BundleDir, so that
// directory is the answer. A build that ships none -- which is now the normal
// case -- never sets it, and the old filepath.Join(BundleDirValue(), name) then
// produced a path relative to the process's working directory, which on iOS is
// "/". The download failed with "open AppleMediaServices: no such file or
// directory" and the resolver below was never consulted, because the download
// path read the file directly instead of going through loadBundle.
//
// So resolve first: loadBundle falls back to Apple on a cache miss, and its
// extractor size- and SHA-256-checks before it writes, which makes the cache
// directory a source as trustworthy as the staged one.
func appleMediaServicesPath() (string, error) {
	dir := BundleDirValue()
	if dir != "" {
		return filepath.Join(dir, "AppleMediaServices"), nil
	}

	if _, err := loadBundle(); err != nil {
		return "", err
	}

	cache, err := assets.CacheDirectory()
	if err != nil {
		return "", fmt.Errorf("sapbridge: %w", err)
	}

	return filepath.Join(cache, "AppleMediaServices"), nil
}

// readBundleDir loads the seven pinned binaries from an explicit directory.
//
// Seven, not four: the loader validates seven, and this reader was left on the
// four-piece profile when the identity service joined it. A staged directory
// therefore failed with "adid is empty or missing" -- a message that reads like
// a corrupt download and is really this function not looking.
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

	adid, err := read("adid")
	if err != nil {
		return assets.Bundle{}, fmt.Errorf("read adid: %w", err)
	}

	coreFP, err := read("CoreFP")
	if err != nil {
		return assets.Bundle{}, fmt.Errorf("read CoreFP: %w", err)
	}

	coreFPICXS, err := read("CoreFP.icxs")
	if err != nil {
		return assets.Bundle{}, fmt.Errorf("read CoreFP.icxs: %w", err)
	}

	fairplayd, err := read("fairplayd")
	if err != nil {
		return assets.Bundle{}, fmt.Errorf("read fairplayd: %w", err)
	}

	kext, err := read("FairPlayIOKit")
	if err != nil {
		return assets.Bundle{}, fmt.Errorf("read FairPlayIOKit: %w", err)
	}

	bundle := assets.Bundle{
		AppleMediaServices: appleMediaServices,
		Commerce:           commerce,
		ADID:               adid,
		CoreFP:             coreFP,
		CoreFPICXS:         coreFPICXS,
		FairPlayD:          fairplayd,
		FairPlayKext:       kext,
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
		ADID:               adid,
		CoreFP:             coreFP,
		CoreFPICXS:         coreFPICXS,
		FairPlayD:          fairplayd,
		FairPlayKext:       kext,
	}, nil
}
