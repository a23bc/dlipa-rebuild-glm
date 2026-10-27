// Command export-cache-pages pulls the shared-cache pages the Store profile
// points at.
//
// The profile's prepared pages contain absolute pointers into the dyld shared
// cache. On macOS the host has that cache mapped, so upstream never needs to
// provide it; in the emulator those pointers land on nothing and the first Store
// request faults. This ships just the pages the pointers reference.
//
// It runs inside the ipatool module because StoreCache.Page is what knows how to
// turn an address into bytes: the dumped files are cache members, not Mach-O
// images, so a naive macho.Open over them finds nothing.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/majd/ipatool/v2/internal/sap/assets"
)

const (
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
	prefix := flag.String("prefix", "", "path prefix of the dumped shared-cache members")
	systemDir := flag.String("system-dir", "", "directory holding the dumped FeatureFlags plists")
	addresses := flag.String("addresses", "", "newline-separated page addresses to extract")
	output := flag.String("output", "", "path to write the page blob to")
	flag.Parse()

	if *prefix == "" || *systemDir == "" || *addresses == "" || *output == "" {
		return fmt.Errorf("-prefix, -system-dir, -addresses and -output are required")
	}

	list, err := readAddresses(*addresses)
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	cache, err := assets.OpenLocalStoreCacheWithSystemFiles(ctx, *prefix, *systemDir)
	if err != nil {
		return fmt.Errorf("open dumped cache: %w", err)
	}

	defer cache.Close()

	buf := make([]byte, 0, len(list)*(8+pageSize))

	var missing int

	for _, addr := range list {
		page, pageErr := cache.Page(addr)
		if pageErr != nil || len(page) != pageSize {
			missing++
			continue
		}

		var head [8]byte
		binary.LittleEndian.PutUint64(head[:], addr)
		buf = append(buf, head[:]...)
		buf = append(buf, page...)
	}

	if missing > 0 {
		fmt.Fprintf(os.Stderr, "warning: %d of %d pages could not be read\n", missing, len(list))
	}

	var plain bytes.Buffer
	plain.WriteString(magic)

	if err = binary.Write(&plain, binary.LittleEndian, uint64(len(buf)/(8+pageSize))); err != nil {
		return err
	}

	plain.Write(buf)

	encoder, err := zstd.NewWriter(nil)
	if err != nil {
		return err
	}

	packed := encoder.EncodeAll(plain.Bytes(), nil)
	encoder.Close()

	if err = os.WriteFile(*output, packed, 0o644); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "wrote %d pages (%d MB) to %s\n", len(buf)/(8+pageSize), len(buf)/(1<<20), *output)

	return nil
}

func readAddresses(path string) ([]uint64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	defer f.Close()

	var out []uint64

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		v, parseErr := strconv.ParseUint(strings.TrimPrefix(line, "0x"), 16, 64)
		if parseErr != nil {
			return nil, fmt.Errorf("bad address %q: %w", line, parseErr)
		}

		out = append(out, v)
	}

	return out, scanner.Err()
}
