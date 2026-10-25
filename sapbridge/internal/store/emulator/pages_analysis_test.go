package emulator

import (
	"context"
	"fmt"
	"sort"
	"testing"

	"github.com/a23bc/dlipa-rebuild/sapbridge/internal/store/profile"
)

// Where do the profile's prepared pages actually live, and how much of the
// address space do they cover? Sharing one guest with the SAP machine only works
// if those ranges do not overlap what the machine already maps; this prints the
// ranges so the question is answered with numbers instead of reasoning.
func TestProfilePageRanges(t *testing.T) {
	data, err := profile.Load(context.Background())
	if err != nil {
		t.Fatalf("load profile: %v", err)
	}

	meta, err := cachedMetadata.load(context.Background(), data.Metadata)
	if err != nil {
		t.Fatalf("load metadata: %v", err)
	}

	pages := meta.profile.Pages
	if len(pages) == 0 {
		t.Fatalf("profile has no pages")
	}

	addresses := make([]uint64, 0, len(pages))
	for _, p := range pages {
		addresses = append(addresses, p.Address)
	}
	sort.Slice(addresses, func(i, j int) bool { return addresses[i] < addresses[j] })

	// Group contiguous pages into regions, the same way open() does.
	var regions [][2]uint64
	start, end := addresses[0], addresses[0]+4096
	for _, a := range addresses[1:] {
		if a == end {
			end += 4096
			continue
		}
		regions = append(regions, [2]uint64{start, end - start})
		start, end = a, a+4096
	}
	regions = append(regions, [2]uint64{start, end - start})

	t.Logf("pages=%d dataBytes=%d regions=%d", len(pages), len(data.Pages), len(regions))
	t.Logf("lowest=%#x highest=%#x", addresses[0], addresses[len(addresses)-1])

	// The machine already occupies these, from its own startup log.
	machine := [][2]uint64{
		{0x100000000, 4096},
		{0x300000000000, 33554432},
		{0x400000000000, 67108864},
		{0x500000000000, 8388608},
	}

	var overlapping int
	for _, r := range regions {
		for _, m := range machine {
			if r[0] < m[0]+m[1] && m[0] < r[0]+r[1] {
				t.Logf("OVERLAP machine: region %#x+%#x with machine %#x+%#x", r[0], r[1], m[0], m[1])
				overlapping++
			}
		}
	}
	t.Logf("regions overlapping the machine's fixed ranges: %d", overlapping)

	// Print the first few regions so the layout is visible.
	for i, r := range regions {
		if i >= 12 {
			t.Logf("... %d more regions", len(regions)-12)
			break
		}
		t.Logf("region %2d: %#012x + %#x", i, r[0], r[1])
	}
	_ = fmt.Sprintf
}
