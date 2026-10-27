package cachepages

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/a23bc/dlipa-rebuild/sapbridge/internal/sap/machimage"
)

// The blob is cut from the shared cache, and AppleMediaServices lives in that
// cache, so the blob carries the framework's own pages. Mapping them over the
// image the runtime already loaded puts the encoded fixups back and every
// pointer in the segment turns into an address that means nothing -- which is
// how resolve promise ended up sending copy to 0xc4c891a2df0ce37.
//
// WithoutSpans is what stops that, and this test runs it against the real blob
// rather than a synthetic one, because the premise (the blob overlaps the
// image) is exactly what would silently change.
func TestWithoutSpansDropsTheLoadedImagesPages(t *testing.T) {
	pages, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if len(pages) == 0 {
		t.Skip("no page blob in this build")
	}

	var spans [][2]uint64

	for _, name := range []string{"AppleMediaServices", "commerce", "CoreFP"} {
		raw, err := os.ReadFile(filepath.Join("../../../../VendorAssets", name))
		if err != nil {
			t.Skipf("asset %s not present: %v", name, err)
		}

		image, err := machimage.Open(name, raw)
		if err != nil {
			t.Fatalf("open %s: %v", name, err)
		}

		spans = append(spans, image.Spans()...)
	}

	kept, dropped := WithoutSpans(pages, spans)
	if dropped == 0 {
		t.Fatal("the blob holds no page inside a loaded image; the filter has nothing to do")
	}

	if len(kept)+dropped != len(pages) {
		t.Fatalf("kept %d + dropped %d != %d", len(kept), dropped, len(pages))
	}

	// The page initWithBag needed before this filter existed. It is outside every
	// image segment, so dropping the images' own pages must not take it with them.
	const needed = 0x1e9881000

	found := false

	for _, page := range kept {
		if page.Address == needed {
			found = true
		}
	}

	if !found {
		t.Fatalf("the filter dropped %#x, which is outside every image", needed)
	}

	for _, page := range kept {
		for _, span := range spans {
			if page.Address >= span[0] && page.Address < span[1] {
				t.Fatalf("%#x survived the filter but is inside %#x+%#x", page.Address, span[0], span[1]-span[0])
			}
		}
	}

	t.Logf("%d pages, %d dropped inside a loaded image, %d kept", len(pages), dropped, len(kept))
}
