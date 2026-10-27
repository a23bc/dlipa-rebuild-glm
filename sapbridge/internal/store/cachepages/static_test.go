package cachepages

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/a23bc/dlipa-rebuild/sapbridge/internal/sap/machimage"
)

const (
	staticAssets = "../../../../VendorAssets"
	staticLo     = 0x100000000
	staticHi     = 0x300000000
)

// staticPages recomputes the list from the vendored images.
//
// Data segments are the statically reachable half of the problem: a pointer
// baked into AppleMediaServices is read the moment the function owning that
// table runs, so its page is worth shipping even if no profile page mentions it.
// That is the case that stopped initWithBag -- the slot at 0x1e660ae58 in
// __DATA_DIRTY points at 0x1e9881478, and the profile-derived window never
// covered the page holding it.
func staticPages(t *testing.T) []uint64 {
	t.Helper()

	pages := map[uint64]struct{}{}

	for _, name := range []string{"AppleMediaServices", "commerce", "CoreFP"} {
		raw, err := os.ReadFile(filepath.Join(staticAssets, name))
		if err != nil {
			t.Skipf("asset %s not present: %v", name, err)
		}

		image, err := machimage.Open(name, raw)
		if err != nil {
			t.Fatalf("open %s: %v", name, err)
		}

		for _, page := range image.DataPointers(staticLo, staticHi) {
			pages[page] = struct{}{}
		}
	}

	out := make([]uint64, 0, len(pages))
	for page := range pages {
		out = append(out, page)
	}

	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })

	return out
}

func renderStatic(pages []uint64) string {
	var buf strings.Builder

	buf.WriteString("# Pages the vendored images point at, inside 0x100000000-0x300000000.\n")
	buf.WriteString("# Regenerate with: UPDATE_STATIC_PAGES=1 go test ./internal/store/cachepages -run TestStaticPagesAreCurrent\n")

	for _, page := range pages {
		buf.WriteString("\n")
		buf.WriteString(hex(page))
	}

	buf.WriteString("\n")

	return buf.String()
}

func hex(value uint64) string {
	const digits = "0123456789abcdef"

	var buf [18]byte
	buf[0] = '0'
	buf[1] = 'x'

	for i := 0; i < 16; i++ {
		buf[2+i] = digits[(value>>(60-4*uint(i)))&0xF]
	}

	return string(buf[:])
}

// TestStaticPagesAreCurrent fails when the committed list no longer matches the
// vendored images, which is what an asset bump looks like.
func TestStaticPagesAreCurrent(t *testing.T) {
	pages := staticPages(t)
	want := renderStatic(pages)

	if os.Getenv("UPDATE_STATIC_PAGES") == "1" {
		if err := os.WriteFile("static-pages.txt", []byte(want), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}

		t.Logf("wrote %d pages", len(pages))

		return
	}

	got, err := os.ReadFile("static-pages.txt")
	if err != nil {
		t.Fatalf("read committed list: %v", err)
	}

	if string(got) != want {
		t.Fatalf("static-pages.txt holds %d pages, the images say %d; rerun with UPDATE_STATIC_PAGES=1",
			countPages(string(got)), len(pages))
	}

	t.Logf("%d pages", len(pages))
}

func countPages(text string) int {
	count := 0

	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "0x") {
			count++
		}
	}

	return count
}
