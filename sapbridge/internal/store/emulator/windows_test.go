package emulator

import (
	"context"
	"encoding/binary"
	"testing"

	"github.com/a23bc/dlipa-rebuild/sapbridge/internal/store/profile"
)

// The shared-cache window used to be a guess: 0x180000000-0x1c0000000. It
// covered 4,847 of the pages the profile points at and missed the rest, which is
// why a pointer read out of AppleMediaServices still landed on nothing after the
// blob was shipped.
//
// Bucketing by the top 32 bits shows where the pointers actually stop: two dense
// gigabytes, a thin third one, then scattered values that are indistinguishable
// from arbitrary data. This test pins that edge so the window is chosen from the
// profile rather than from memory.
func TestPointerWindowEdge(t *testing.T) {
	data, err := profile.Load(context.Background())
	if err != nil {
		t.Fatalf("load profile: %v", err)
	}

	meta, err := cachedMetadata.load(context.Background(), data.Metadata)
	if err != nil {
		t.Fatalf("load metadata: %v", err)
	}

	type bucket struct {
		pages map[uint64]struct{}
		hits  int
	}

	buckets := map[uint64]*bucket{}

	for _, p := range meta.profile.Pages {
		page := data.Pages[p.Offset : p.Offset+4096]
		for off := 0; off+8 <= len(page); off += 8 {
			v := binary.LittleEndian.Uint64(page[off:])
			if v < 0x100000000 {
				continue
			}

			top := v >> 32
			if buckets[top] == nil {
				buckets[top] = &bucket{pages: map[uint64]struct{}{}}
			}

			buckets[top].pages[v&^0xFFF] = struct{}{}
			buckets[top].hits++
		}
	}

	below := 0
	belowPages := 0

	for top := uint64(1); top <= 2; top++ {
		if b := buckets[top]; b != nil {
			below += b.hits
			belowPages += len(b.pages)

			t.Logf("[%#xG, +1G) pointers=%d pages=%d", top, b.hits, len(b.pages))
		}
	}

	// Density, not page count: arbitrary 64-bit words are almost all above 4G and
	// spread over half a million pages, so counting pages there proves nothing.
	// A real pointer population is dense in a few gigabytes.
	widest := 0

	for top, b := range buckets {
		if top > 4 && b.hits > widest {
			widest = b.hits
			t.Logf("densest bucket above 0x400000000: [%#xG,+1G) pointers=%d pages=%d", top, b.hits, len(b.pages))
		}
	}

	if below < 100000 {
		t.Fatalf("only %d pointers below 0x300000000; the window assumption no longer holds", below)
	}

	if widest*10 > below {
		t.Fatalf("%d pointers above 0x400000000 against %d below 0x300000000: no clean edge", widest, below)
	}

	t.Logf("pointers below 0x300000000=%d (%d pages), densest bucket above=%d", below, belowPages, widest)
}
