// Command export-cache-pages extracts the shared-cache pages the Store profile
// points at.
//
// The profile's prepared pages contain 68,892 absolute pointers into the dyld
// shared cache (0x180000000-0x1c0000000). Upstream never has to provide those
// pages because on macOS the real cache is already mapped in the host process; in
// this emulator the pointers have nothing to point at, and the first Store request
// dies reading through one of them.
//
// Only the pages actually referenced are needed: 4,847 of them, about 19 MB. This
// command finds each one in the dumped cache members and writes them out as
// (address, 4096 bytes) records.
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"sort"

	"github.com/a23bc/dlipa-rebuild/sapbridge/internal/store/cachepages"
	"github.com/a23bc/dlipa-rebuild/sapbridge/internal/store/emulator"
	storeprofile "github.com/a23bc/dlipa-rebuild/sapbridge/internal/store/profile"
)

const (
	cacheLo = 0x180000000
	cacheHi = 0x1c0000000
	pageSize = 4096
	magic    = "DSHPAGES1"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	systemDir := flag.String("addresses", "", "path to write the referenced page addresses to")
	flag.Parse()

	if *systemDir == "" {
		return fmt.Errorf("-addresses is required")
	}

	addresses, err := referencedPages(context.Background())
	if err != nil {
		return fmt.Errorf("read profile: %w", err)
	}

	var buf bytes.Buffer

	for _, addr := range addresses {
		fmt.Fprintf(&buf, "%#x\n", addr)
	}

	if err = os.WriteFile(*systemDir, buf.Bytes(), 0o644); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "wrote %d addresses to %s\n", len(addresses), *systemDir)

	return nil
}

// referencedPages collects the distinct 4 KiB pages the profile's prepared pages
// point into, inside the shared-cache range, plus the pages the vendored images
// point at.
//
// The two sets answer different questions. The profile is a snapshot of dynamic
// state, so it only reveals pointers the process happened to hold. A pointer
// compiled into a data segment never appears there, and that is the one that
// stopped initWithBag: __DATA_DIRTY in AppleMediaServices holds 0x1e9881478, a
// page no profile scan had ever listed.
func referencedPages(ctx context.Context) ([]uint64, error) {
	data, err := storeprofile.Load(ctx)
	if err != nil {
		return nil, err
	}

	pages, err := emulator.PreparedPages(ctx, data.Metadata)
	if err != nil {
		return nil, fmt.Errorf("decode profile metadata: %w", err)
	}

	seen := map[uint64]struct{}{}

	for _, pg := range pages {
		if pg.Offset+pageSize > uint64(len(data.Pages)) {
			continue
		}

		page := data.Pages[pg.Offset : pg.Offset+pageSize]

		for off := 0; off+8 <= len(page); off += 8 {
			v := binary.LittleEndian.Uint64(page[off:])
			if v < cacheLo || v >= cacheHi {
				continue
			}

			seen[v&^uint64(pageSize-1)] = struct{}{}
		}
	}

	static := 0

	for _, address := range cachepages.StaticPages() {
		if _, ok := seen[address]; ok {
			continue
		}

		seen[address] = struct{}{}
		static++
	}

	fmt.Fprintf(os.Stderr, "profile pages=%d, static pages added=%d, total=%d\n", len(seen)-static, static, len(seen))

	out := make([]uint64, 0, len(seen))
	for a := range seen {
		out = append(out, a)
	}

	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })

	return out, nil
}
