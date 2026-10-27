package cachepages

import "sort"

// Run is a group of contiguous pages, so the guest can map them with one call
// instead of one per page.
type Run struct {
	Address uint64
	Data    []byte
}

// Runs groups contiguous pages. The blob carries 9,758 pages but only 4,198
// runs: every mapping is a region insert in the engine, and at this size the
// per-call cost is what makes opening the runtime slow rather than the bytes.
//
// The returned data is copied, so callers may keep it after the pages are
// released.
func Runs(pages []Page) []Run {
	if len(pages) == 0 {
		return nil
	}

	sorted := make([]Page, len(pages))
	copy(sorted, pages)

	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Address < sorted[j].Address })

	out := make([]Run, 0, len(sorted)/2+1)

	for _, page := range sorted {
		last := len(out) - 1

		if last >= 0 && out[last].Address+uint64(len(out[last].Data)) == page.Address {
			out[last].Data = append(out[last].Data, page.Data...)

			continue
		}

		out = append(out, Run{Address: page.Address, Data: append([]byte(nil), page.Data...)})
	}

	return out
}
