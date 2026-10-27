package emulator

import (
	"context"
	"encoding/binary"
	"sort"
	"testing"

	"github.com/a23bc/dlipa-rebuild/sapbridge/internal/store/profile"
)

// How much memory would it take to back every address the profile's prepared
// pages actually point at? Only referenced pages matter: the guest never runs the
// rest of the shared cache, so the cost is distinct 4 KiB pages, not whole images.
func TestReferencedPageBudget(t *testing.T) {
	data, err := profile.Load(context.Background())
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	meta, err := cachedMetadata.load(context.Background(), data.Metadata)
	if err != nil {
		t.Fatalf("meta: %v", err)
	}

	const lo, hi = 0x180000000, 0x1c0000000

	pages := map[uint64]struct{}{}
	bucketPages := map[uint64]map[uint64]struct{}{}

	for _, p := range meta.profile.Pages {
		page := data.Pages[p.Offset : p.Offset+4096]
		for off := 0; off+8 <= len(page); off += 8 {
			v := binary.LittleEndian.Uint64(page[off:])
			if v < lo || v >= hi {
				continue
			}
			pg := v &^ 0xFFF
			pages[pg] = struct{}{}
			b := pg >> 24
			if bucketPages[b] == nil {
				bucketPages[b] = map[uint64]struct{}{}
			}
			bucketPages[b][pg] = struct{}{}
		}
	}

	t.Logf("distinct referenced pages=%d  cost=%d bytes (%.1f MB)", len(pages), len(pages)*4096, float64(len(pages))*4096/(1<<20))

	type row struct {
		bucket uint64
		pages  int
	}
	rows := make([]row, 0, len(bucketPages))
	for b, set := range bucketPages {
		rows = append(rows, row{b, len(set)})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].pages > rows[j].pages })

	for i, r := range rows {
		if i >= 10 {
			break
		}
		t.Logf("bucket %#x: %d pages (%.2f MB)", r.bucket<<24, r.pages, float64(r.pages)*4096/(1<<20))
	}
	t.Logf("total buckets referenced=%d", len(rows))
}
