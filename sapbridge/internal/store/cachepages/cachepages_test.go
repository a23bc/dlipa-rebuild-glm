package cachepages

import "testing"

func TestBlobDecodes(t *testing.T) {
	if !Available() {
		t.Fatalf("no page blob is embedded")
	}

	pages, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if len(pages) == 0 {
		t.Fatalf("blob carries no pages")
	}

	t.Logf("pages=%d first=%#x last=%#x", len(pages), pages[0].Address, pages[len(pages)-1].Address)

	for _, p := range pages {
		if len(p.Data) != pageSize {
			t.Fatalf("page %#x has %d bytes", p.Address, len(p.Data))
		}
		if p.Address&(pageSize-1) != 0 {
			t.Fatalf("page %#x is not page aligned", p.Address)
		}
	}
}
