package emulator

import (
	"context"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/a23bc/dlipa-rebuild/sapbridge/internal/store/profile"
)

// Do the profile's prepared pages contain absolute pointers into the range where
// CoreFP lives in the shared cache? The machine loads CoreFP at 0x100000000000
// instead of its natural base, so any such pointer is stale by construction.
func TestProfilePointersIntoCoreFPRange(t *testing.T) {
	data, err := profile.Load(context.Background())
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	meta, err := cachedMetadata.load(context.Background(), data.Metadata)
	if err != nil {
		t.Fatalf("meta: %v", err)
	}

	const lo, hi = 0x180000000, 0x1c0000000

	var hits, total int
	buckets := map[uint64]int{}

	for _, p := range meta.profile.Pages {
		page := data.Pages[p.Offset : p.Offset+4096]
		for off := 0; off+8 <= len(page); off += 8 {
			v := binary.LittleEndian.Uint64(page[off:])
			if v >= lo && v < hi {
				hits++
				buckets[v>>24]++
			}
			total++
		}
	}

	t.Logf("pages=%d words=%d pointers in [%#x,%#x)=%d", len(meta.profile.Pages), total, lo, hi, hits)

	top := 0
	for k, n := range buckets {
		if n > top {
			top = n
		}
		_ = k
	}
	t.Logf("distinct 16MB buckets=%d", len(buckets))
	for k, n := range buckets {
		if n > 100 {
			t.Logf("bucket %#x: %d", k<<24, n)
		}
	}
	_ = fmt.Sprint
}
