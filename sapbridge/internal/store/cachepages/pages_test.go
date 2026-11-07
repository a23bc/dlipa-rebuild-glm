package cachepages

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// The page blob is decompressed once for the whole test binary, and the
// VendorAssets check happens before any decompression.
//
// Both of those were missing. Load() inflates 16.4 MB into roughly 40 MB and
// caches nothing, and three tests in this package each called it separately;
// and TestWithoutSpans decompressed the blob first and only then discovered
// that VendorAssets/ is not in the repository -- it is gitignored, so on a CI
// runner it never is. That is 40 MB of allocation paid in order to reach a
// skip. Locally uncached the package finishes in a couple of seconds; the same
// work on a GitHub runner measured over three minutes and tripped the package
// timeout, which is how a test gate gets ignored rather than fixed.

var vendorAssetNames = []string{"AppleMediaServices", "commerce", "CoreFP"}

// vendorAssets reads the four extracted Apple binaries, or reports that they
// are not here. Nothing has been decompressed by the time it answers.
func vendorAssets() (map[string][]byte, bool) {
	raw := make(map[string][]byte, len(vendorAssetNames))

	for _, name := range vendorAssetNames {
		data, err := os.ReadFile(filepath.Join("../../../../VendorAssets", name))
		if err != nil {
			return nil, false
		}

		raw[name] = data
	}

	return raw, true
}

var pagesOnce = struct {
	once  sync.Once
	pages []Page
	err   error
}{}

// loadPages answers the blob's pages for any test, decoding at most once per
// run of the binary. It skips rather than fails when the build carries no blob,
// because a blob is only present after the regeneration workflow has produced
// one.
func loadPages(t *testing.T) []Page {
	t.Helper()

	pagesOnce.once.Do(func() {
		pagesOnce.pages, pagesOnce.err = Load()
	})

	if pagesOnce.err != nil {
		t.Fatalf("load: %v", pagesOnce.err)
	}

	if len(pagesOnce.pages) == 0 {
		t.Skip("no page blob in this build")
	}

	return pagesOnce.pages
}
