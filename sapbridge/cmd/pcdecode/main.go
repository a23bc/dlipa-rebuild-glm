// Command pcdecode answers "what code is at this guest address".
//
// A device log gives a PC and a few registers; the asset gives everything else.
// Symbolising the PC is the difference between "x16 is bad" and "the caller
// asked for +[Foo shared] and the class ref was never bound".
//
//	go run ./cmd/pcdecode -asset ../../VendorAssets/AppleMediaServices 0x1a2a0621c 0x1a2b4cdac
package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
)

func main() {
	asset := flag.String("asset", "../VendorAssets/AppleMediaServices", "Mach-O to inspect")
	sym := flag.String("sym", "", "list symbols whose name contains this substring")
	rng := flag.String("range", "", "list symbols and function starts in lo,hi")
	mem := flag.String("bytes", "", "dump raw file bytes at addr,len")
	window := flag.Int("window", 0x40, "bytes to dump from the function start")
	flag.Parse()

	raw, err := os.ReadFile(*asset)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read %s: %v\n", *asset, err)
		os.Exit(1)
	}

	file, err := macho.NewFile(bytes.NewReader(raw))
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse %s: %v\n", *asset, err)
		os.Exit(1)
	}

	functions := file.GetFunctions()
	sort.Slice(functions, func(a, b int) bool { return functions[a].StartAddr < functions[b].StartAddr })

	symbols := map[uint64][]string{}

	if file.Symtab != nil {
		for _, sym := range file.Symtab.Syms {
			if sym.Value != 0 {
				symbols[sym.Value] = append(symbols[sym.Value], sym.Name)
			}
		}
	}

	if *mem != "" {
		dumpBytes(file, raw, *mem)
		return
	}

	if *rng != "" {
		listRange(file, *rng)
		return
	}

	if *sym != "" {
		listSymbols(file, *sym)
		return
	}

	for _, arg := range flag.Args() {
		pc, err := strconv.ParseUint(arg, 0, 64)
		if err != nil {
			fmt.Fprintf(os.Stderr, "bad address %q: %v\n", arg, err)
			continue
		}

		fmt.Printf("\n=== %#x ===\n", pc)
		describeSection(file, pc)

		fn := findFunction(functions, pc)
		if fn == nil {
			fmt.Printf("  no function start at or below %#x\n", pc)
			continue
		}

		fmt.Printf("  function %#x..%#x (offset +%#x)\n", fn.StartAddr, fn.EndAddr, pc-fn.StartAddr)

		names := symbols[fn.StartAddr]
		if len(names) == 0 {
			fmt.Printf("  symbol   (none)\n")
		}

		for _, name := range names {
			fmt.Printf("  symbol   %s\n", name)
		}

		dump(file, raw, fn.StartAddr, uint64(*window), pc)
	}
}

func describeSection(file *macho.File, pc uint64) {
	for _, section := range file.Sections {
		start := section.Addr
		end := section.Addr + section.Size
		if pc < start || pc >= end {
			continue
		}

		fmt.Printf("  section  %s,%s %#x+%#x flags=%#x offset=+%#x\n",
			section.Seg, section.Name, section.Addr, section.Size,
			uint32(section.Flags), pc-section.Addr)

		return
	}

	fmt.Printf("  section  (not inside any section)\n")
}

func findFunction(functions []types.Function, pc uint64) *types.Function {
	index := sort.Search(len(functions), func(i int) bool { return functions[i].StartAddr > pc })
	if index == 0 {
		return nil
	}

	fn := &functions[index-1]
	if pc >= fn.EndAddr && fn.EndAddr != 0 {
		return nil
	}

	return fn
}

func dump(file *macho.File, raw []byte, start, window, mark uint64) {
	for _, section := range file.Sections {
		if start < section.Addr || start >= section.Addr+section.Size {
			continue
		}

		base := section.Offset + uint32(start-section.Addr)

		for offset := uint64(0); offset < window; offset += 4 {
			pos := base + uint32(offset)
			if int(pos)+4 > len(raw) {
				return
			}

			prefix := "   "
			if start+offset == mark {
				prefix = "  >"
			}

			fmt.Printf("%s %#x: %08x\n", prefix, start+offset, binary.LittleEndian.Uint32(raw[pos:]))
		}

		return
	}
}

func listSymbols(file *macho.File, needle string) {
	if file.Symtab == nil {
		fmt.Println("no symtab")
		return
	}

	matches := 0
	for _, sym := range file.Symtab.Syms {
		if !strings.Contains(sym.Name, needle) {
			continue
		}
		fmt.Printf("  %#x %s\n", sym.Value, sym.Name)
		matches++
	}
	fmt.Printf("  %d matches for %q (symtab %d entries)\n", matches, needle, len(file.Symtab.Syms))
}

func listRange(file *macho.File, spec string) {
	parts := strings.SplitN(spec, ",", 2)
	if len(parts) != 2 {
		fmt.Fprintf(os.Stderr, "range wants lo,hi\n")
		return
	}

	lo, _ := strconv.ParseUint(parts[0], 0, 64)
	hi, _ := strconv.ParseUint(parts[1], 0, 64)

	type entry struct {
		addr uint64
		kind string
		name string
	}

	var entries []entry

	if file.Symtab != nil {
		for _, sym := range file.Symtab.Syms {
			if sym.Value >= lo && sym.Value < hi {
				entries = append(entries, entry{sym.Value, "sym  ", sym.Name})
			}
		}
	}

	for _, fn := range file.GetFunctions() {
		if fn.StartAddr >= lo && fn.StartAddr < hi {
			entries = append(entries, entry{fn.StartAddr, "start", ""})
		}
	}

	sort.Slice(entries, func(a, b int) bool {
		if entries[a].addr != entries[b].addr {
			return entries[a].addr < entries[b].addr
		}
		return entries[a].kind < entries[b].kind
	})

	for _, e := range entries {
		fmt.Printf("  %#x %s %s\n", e.addr, e.kind, e.name)
	}
}

// dumpBytes prints what the file holds at a guest address, which is the only
// way to tell "the loader left this slot zero" from "it was always zero".
func dumpBytes(file *macho.File, raw []byte, spec string) {
	parts := strings.SplitN(spec, ",", 2)
	if len(parts) != 2 {
		fmt.Fprintf(os.Stderr, "bytes wants addr,len\n")
		return
	}

	addr, _ := strconv.ParseUint(parts[0], 0, 64)
	length, _ := strconv.ParseUint(parts[1], 0, 64)

	for _, section := range file.Sections {
		if addr < section.Addr || addr >= section.Addr+section.Size {
			continue
		}

		base := uint64(section.Offset) + (addr - section.Addr)
		if base+length > uint64(len(raw)) {
			fmt.Fprintf(os.Stderr, "range exceeds file\n")
			return
		}

		fmt.Printf("  section %s,%s  file offset %#x\n", section.Seg, section.Name, base)

		for offset := uint64(0); offset < length; offset += 8 {
			chunk := raw[base+offset : base+offset+8]
			word := binary.LittleEndian.Uint64(chunk)
			fmt.Printf("  %#x: %016x  (%d)\n", addr+offset, word, word)
		}

		return
	}

	fmt.Printf("  %#x is not inside any section\n", addr)
}
