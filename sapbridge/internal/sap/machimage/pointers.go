package machimage

import (
	"encoding/binary"
	"sort"
)

// DataPointers reports the distinct pages this image's data segments point at,
// restricted to [lo, hi).
//
// Instruction sections are skipped: every fourth byte there is an opcode, and a
// scan over them produces addresses that are not pointers at all. What is left
// is tables, class data and literal pointers, which the code reads as soon as
// the function owning them runs. Those are worth shipping the target page for
// even when no profile page mentions it.
func (i *Image) DataPointers(lo, hi uint64) []uint64 {
	pages := map[uint64]struct{}{}

	for _, item := range i.segments {
		if item.name == "__PAGEZERO" || item.name == "__TEXT" || item.name == "__LINKEDIT" {
			continue
		}

		end := item.fileOff + item.fileSize
		if end > uint64(len(i.data)) {
			continue
		}

		data := i.data[item.fileOff:end]

		for offset := 0; offset+8 <= len(data); offset += 8 {
			value := binary.LittleEndian.Uint64(data[offset:])
			if value < lo || value >= hi {
				continue
			}

			pages[value&^0xFFF] = struct{}{}
		}
	}

	out := make([]uint64, 0, len(pages))
	for page := range pages {
		out = append(out, page)
	}

	sort.Slice(out, func(a, b int) bool { return out[a] < out[b] })

	return out
}

// Spans reports the guest ranges this image occupies, as [start, end) pairs in
// file address terms (the caller adds the slide if it loaded elsewhere).
//
// A cache page that falls inside one of these is not the guest's copy of that
// memory: Load already wrote it with the fixups applied. Mapping the cache
// version over it puts the undecoded chained fixups back, and the first pointer
// read out of that segment is garbage.
func (i *Image) Spans() [][2]uint64 {
	var out [][2]uint64

	// Before relocation loadedBase is zero, so fall back to the file address.
	loaded := i.loadedBase
	if loaded == 0 {
		loaded = i.base
	}

	for _, item := range i.segments {
		if item.name == "__PAGEZERO" || item.size == 0 {
			continue
		}

		start, overflow := add(loaded, item.address-i.base)
		if overflow {
			continue
		}

		out = append(out, [2]uint64{start, start + item.size})
	}

	return out
}
