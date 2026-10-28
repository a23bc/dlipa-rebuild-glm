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
	cacheLo  = 0x180000000
	cacheHi  = 0x1c0000000
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
	addressesPath := flag.String("addresses", "", "path to write the referenced page addresses to")
	checkPath := flag.String("check", "", "path to a page blob to verify against ExtraPages, instead of writing addresses")
	flag.Parse()

	if *checkPath != "" {
		return checkBlob(*checkPath)
	}

	if *addressesPath == "" {
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

	if err = os.WriteFile(*addressesPath, buf.Bytes(), 0o644); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "wrote %d addresses to %s\n", len(addresses), *addressesPath)

	return nil
}

// checkBlob reports whether a built blob carries the pages it must, and how much
// of the exploration window it managed to cover.
//
// The exporter warns and skips when the cache cannot resolve an address, so a
// blob missing a page looks exactly like a good one until the device faults on it
// again. Only the required list is fatal: the window deliberately spans more than
// the cache contains, and a window page that does not resolve is an answer about
// the cache rather than a fault in the export. The window counts still go to the
// log, because they are how the window gets trimmed.
func checkBlob(path string) error {
	compressed, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read blob: %w", err)
	}

	pages, err := cachepages.Decode(compressed)
	if err != nil {
		return fmt.Errorf("decode blob: %w", err)
	}

	present := make(map[uint64]struct{}, len(pages))
	for _, page := range pages {
		present[page.Address] = struct{}{}
	}

	has := func(address uint64) bool {
		_, ok := present[address]

		return ok
	}

	required := cachepages.RequiredPages()

	var missing []uint64

	for _, address := range required {
		if !has(address) {
			missing = append(missing, address)
		}
	}

	window := cachepages.ExtraPages()

	covered := 0

	for _, address := range window {
		if has(address) {
			covered++
		}
	}

	fmt.Fprintf(os.Stderr, "blob %s: %d pages\n", path, len(pages))
	fmt.Fprintf(os.Stderr, "  required: %d of %d present\n", len(required)-len(missing), len(required))
	fmt.Fprintf(os.Stderr, "  window:   %d of %d present (%d absent from the pinned cache)\n",
		covered, len(window), len(window)-covered)

	if len(missing) == 0 {
		return nil
	}

	// A handful of addresses is readable; a whole set missing is not, and the
	// count alone says which happened.
	for i, address := range missing {
		if i >= 8 {
			fmt.Fprintf(os.Stderr, "  ... and %d more\n", len(missing)-i)

			break
		}

		fmt.Fprintf(os.Stderr, "  missing %#x\n", address)
	}

	return fmt.Errorf("blob lacks %d required page(s); the export skipped them", len(missing))
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

	extra := 0

	for _, address := range cachepages.ExtraPages() {
		if _, ok := seen[address]; ok {
			continue
		}

		seen[address] = struct{}{}
		extra++
	}

	fmt.Fprintf(os.Stderr, "profile pages=%d, static pages added=%d, extra pages added=%d, total=%d\n",
		len(seen)-static-extra, static, extra, len(seen))

	out := make([]uint64, 0, len(seen))
	for a := range seen {
		out = append(out, a)
	}

	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })

	return out, nil
}
