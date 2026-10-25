// Package cachepages holds the shared-cache pages the Store profile points at.
//
// The profile was generated on a system where the dyld shared cache is mapped at
// 0x180000000. The guest has no such cache, so every absolute pointer into it
// lands on nothing. This package carries just the pages those pointers reference,
// extracted by scripts/export-cache-pages.
package cachepages

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"fmt"

	"github.com/klauspost/compress/zstd"
)

//go:embed pages.bin.zst
var compressed []byte

const (
	magic     = "DSHPAGES1"
	pageSize  = 4096
	entrySize = 8 + pageSize
)

// Page is one 4 KiB page of the shared cache, at the address the profile expects.
type Page struct {
	Address uint64
	Data    []byte
}

// Available reports whether a page blob was built into this binary. The blob is
// empty until the regeneration workflow has produced one.
func Available() bool { return len(compressed) > 0 }

// Load decodes the embedded pages.
func Load() ([]Page, error) {
	if len(compressed) == 0 {
		return nil, nil
	}

	decoder, err := zstd.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, fmt.Errorf("open page blob: %w", err)
	}

	defer decoder.Close()

	raw, err := decoder.DecodeAll(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("decode page blob: %w", err)
	}

	if len(raw) < len(magic)+8 || string(raw[:len(magic)]) != magic {
		return nil, fmt.Errorf("page blob has an unexpected header")
	}

	count := binary.LittleEndian.Uint64(raw[len(magic):])
	data := raw[len(magic)+8:]

	if uint64(len(data)) != count*entrySize {
		return nil, fmt.Errorf("page blob declares %d pages but carries %d bytes", count, len(data))
	}

	pages := make([]Page, 0, count)

	for i := uint64(0); i < count; i++ {
		off := i * entrySize
		pages = append(pages, Page{
			Address: binary.LittleEndian.Uint64(data[off:]),
			Data:    data[off+8 : off+entrySize],
		})
	}

	return pages, nil
}
