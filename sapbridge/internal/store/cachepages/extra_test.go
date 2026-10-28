package cachepages

import "testing"

// TestExtraPagesAreUsable guards the shape of the hand-maintained list. It is
// edited at the worst possible moment -- a device has just faulted and the blob
// is about to be rebuilt from a 6.6 GB download -- so a typo here costs a full
// run to find.
func TestExtraPagesAreUsable(t *testing.T) {
	pages := ExtraPages()

	if len(pages) == 0 {
		t.Fatal("extra-pages.txt parsed to nothing")
	}

	const (
		cacheLo = 0x180000000
		cacheHi = 0x1c0000000
	)

	for i, address := range pages {
		if address%pageSize != 0 {
			t.Fatalf("page %#x is not page-aligned", address)
		}

		if address < cacheLo || address >= cacheHi {
			t.Fatalf("page %#x is outside the shared-cache range %#x-%#x", address, cacheLo, cacheHi)
		}

		if i > 0 && pages[i-1] >= address {
			t.Fatalf("page %#x follows %#x; the list must be ascending and distinct", address, pages[i-1])
		}
	}
}

// TestExtraPagesCoverTheObservedFault pins the reason the list exists. Dropping
// the window by accident would put signing back where it was, and nothing else
// in the build would notice.
func TestExtraPagesCoverTheObservedFault(t *testing.T) {
	const fault = 0x1880de740
	const page = fault &^ (pageSize - 1)

	for _, address := range ExtraPages() {
		if address == page {
			return
		}
	}

	t.Fatalf("page %#x holding the observed signing fault is not in extra-pages.txt", page)
}
