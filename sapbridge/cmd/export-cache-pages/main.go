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
	"encoding/json"
	"debug/macho"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	profileformat "github.com/a23bc/dlipa-rebuild/sapbridge/internal/store/profile/format"
	storeprofile "github.com/a23bc/dlipa-rebuild/sapbridge/internal/store/profile"
	"github.com/klauspost/compress/zstd"
)

const (
	cacheLo = 0x180000000
	cacheHi = 0x1c0000000
	pageSize = 4096
	magic    = "DSHPAGES1"
)

// segment maps a guest address range to a byte range inside a dumped file.
type segment struct {
	addr, size uint64
	file       string
	offset     uint64
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	systemDir := flag.String("system-dir", "", "directory holding the dumped dyld-cache members")
	output := flag.String("output", "", "path to write the page blob to")
	flag.Parse()

	if *systemDir == "" || *output == "" {
		return fmt.Errorf("-system-dir and -output are required")
	}

	segments, err := index(*systemDir)
	if err != nil {
		return fmt.Errorf("index dumped members: %w", err)
	}

	addresses, err := referencedPages(context.Background())
	if err != nil {
		return fmt.Errorf("read profile: %w", err)
	}

	buf := make([]byte, 0, len(addresses)*4104)

	page := make([]byte, pageSize)

	var missing int

	for _, addr := range addresses {
		seg := find(segments, addr)
		if seg == nil {
			missing++
			continue
		}

		if err = readPage(*seg, addr, page); err != nil {
			return fmt.Errorf("read page %#x from %s: %w", addr, seg.file, err)
		}

		var head [8]byte
		binary.LittleEndian.PutUint64(head[:], addr)
		buf = append(buf, head[:]...)
		buf = append(buf, page...)
	}

	if missing > 0 {
		fmt.Fprintf(os.Stderr, "warning: %d pages had no backing member\n", missing)
	}

	var plain bytes.Buffer
	plain.WriteString(magic)

	if err = binary.Write(&plain, binary.LittleEndian, uint64(len(buf)/4104)); err != nil {
		return err
	}

	plain.Write(buf)

	encoder, err := zstd.NewWriter(nil)
	if err != nil {
		return err
	}

	packed := encoder.EncodeAll(plain.Bytes(), nil)
	encoder.Close()

	out, err := os.Create(*output)
	if err != nil {
		return err
	}

	if _, err = out.Write(packed); err != nil {
		return err
	}

	if err = out.Close(); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "wrote %d pages (%d MB) to %s\n", len(buf)/4104, len(buf)/(1<<20), *output)

	return nil
}

// referencedPages collects the distinct 4 KiB pages the profile's prepared pages
// point into, inside the shared-cache range.
func referencedPages(ctx context.Context) ([]uint64, error) {
	data, err := storeprofile.Load(ctx)
	if err != nil {
		return nil, err
	}

	raw := data.Metadata

	// The metadata blob is zstd-compressed JSON; fall back to raw JSON so the
	// command keeps working if the encoding ever changes.
	if decoder, derr := zstd.NewReader(bytes.NewReader(raw)); derr == nil {
		if decoded, decodeErr := decoder.DecodeAll(nil, nil); decodeErr == nil {
			raw = decoded
		}

		decoder.Close()
	}

	var prof profileformat.Profile
	if err = json.Unmarshal(raw, &prof); err != nil {
		return nil, fmt.Errorf("decode profile metadata: %w", err)
	}

	seen := map[uint64]struct{}{}

	for _, pg := range prof.Pages {
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

	out := make([]uint64, 0, len(seen))
	for a := range seen {
		out = append(out, a)
	}

	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })

	return out, nil
}

func index(dir string) ([]segment, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var out []segment

	for _, e := range entries {
		if e.IsDir() {
			continue
		}

		path := filepath.Join(dir, e.Name())

		f, err := macho.Open(path)
		if err != nil {
			// Not a Mach-O (plists, icxs). Ignore: the profile only points at code.
			continue
		}

		for _, load := range f.Loads {
			seg, ok := load.(*macho.Segment)
			if !ok || seg.Filesz == 0 {
				continue
			}

			out = append(out, segment{addr: seg.Addr, size: seg.Filesz, file: path, offset: uint64(seg.Offset)})
		}

		f.Close()
	}

	return out, nil
}

func find(segments []segment, addr uint64) *segment {
	for i := range segments {
		if addr >= segments[i].addr && addr < segments[i].addr+segments[i].size {
			return &segments[i]
		}
	}

	return nil
}

func readPage(seg segment, addr uint64, dst []byte) error {
	f, err := os.Open(seg.file)
	if err != nil {
		return err
	}

	defer f.Close()

	off := int64(seg.offset) + int64(addr-seg.addr)

	n, err := f.ReadAt(dst, off)
	if err != nil && err != io.EOF {
		return err
	}

	for i := n; i < len(dst); i++ {
		dst[i] = 0
	}

	return nil
}
