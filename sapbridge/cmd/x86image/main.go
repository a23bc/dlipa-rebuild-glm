// Command x86image turns a macOS x86-64 dylib into a loadable guest image.
//
// The TCI build of Unicorn interprets x86-64 without needing executable
// memory, which is the only way to run code on this device. But the guest
// still has to be laid out the way the binary expects, and its imports still
// have to resolve. Doing that work at run time inside the emulator would mean
// writing a dynamic linker in C on a device where a mistake costs a rebuild
// and a manual install.
//
// So the split is: all the Mach-O reading happens here, offline, and the
// emulator only has to place bytes and patch addresses. The output is a flat
// container the C side can walk without a parser:
//
//	magic "X64I", version, counts
//	segments   - name, vmaddr, vmsize, file content
//	imports    - symbol names, in slot order
//	rebases    - guest addresses holding an interior pointer
//	binds      - guest address, slot index, addend
//	entries    - exported names the caller may invoke
//
// Every address in the container is a guest virtual address from the binary's
// own link-time layout; the loader adds the base it chose.
//
// Usage:
//
//	x86image -in CoreFP -out corefp.x64i
//	x86image -in CoreFP -report
package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"sort"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
)

const (
	magic   = "X64I"
	version = 1

	maxName = 128
)

// The entry points the SAP machine resolves. Kept here so the report can say
// whether the binary actually exports what the caller will ask for.
var wantedEntries = []string{
	"_WIn9UJ86JKdV4dM", "_X46O5IeS", "_YlCJ3lg",
	"_dku592fbFAj", "_fdjkDSAFjklaf2s", "_lxpgvVMLd0S7uRl",
	"_cp2g1b9ro", "_Mib5yocT", "_Fc3vhtJDvr", "_IPaI1oem5iL", "_jEHf8Xzsv8K",
}

func main() {
	in := flag.String("in", "", "path to a thin macOS x86-64 Mach-O")
	out := flag.String("out", "", "write the guest image here")
	report := flag.Bool("report", false, "print the layout instead of writing")
	flag.Parse()

	if *in == "" {
		fmt.Fprintln(os.Stderr, "usage: x86image -in <binary> [-out <file> | -report]")
		os.Exit(2)
	}

	raw, err := os.ReadFile(*in)
	if err != nil {
		fail("read input: %v", err)
	}

	file, slice, err := openX86(raw)
	if err != nil {
		fail("parse input: %v", err)
	}

	image, err := build(file, slice)
	if err != nil {
		fail("build image: %v", err)
	}

	if *report {
		image.reportSections(file)
		image.report()
		return
	}

	if *out == "" {
		fail("nothing to do: pass -report or -out")
	}

	encoded, err := image.encode()
	if err != nil {
		fail("encode: %v", err)
	}

	if err := os.WriteFile(*out, encoded, 0o644); err != nil {
		fail("write output: %v", err)
	}

	fmt.Printf("wrote %s (%d bytes): %d segments, %d imports, %d rebases, %d binds\n",
		*out, len(encoded), len(image.segments), len(image.imports),
		len(image.rebases), len(image.binds))
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

type segment struct {
	name    string
	vmaddr  uint64
	vmsize  uint64
	prot    uint32
	content []byte
}

type bind struct {
	addr   uint64
	slot   int32
	addend int32
}

type entry struct {
	name string
	addr uint64
}

type image struct {
	segments []segment
	imports  []string
	rebases         []uint64
	binds           []bind
	entries         []entry
	clampedAddends  int
}

// openX86 picks the x86-64 slice and refuses anything else.
//
// The refusal matters. A first version fell back to whichever slice the thin
// parser found, which silently produced an image from an arm64 binary: the
// counts came out as 4 segments and 9792 rebases instead of 3 and 1004, and
// nothing failed. A wrong-architecture image would have been installed on a
// device and debugged as if it were a loader problem.
// The slice bytes are returned alongside the file because segment file
// offsets are relative to the slice, not to the archive. Indexing the fat file
// with them silently copies the wrong region: the first attempt produced an
// image whose entry point held the fat header's neighbours, and the guest
// executed garbage until it read from address 0x69.
func openX86(raw []byte) (*macho.File, []byte, error) {
	if fat, err := macho.NewFatFile(bytes.NewReader(raw)); err == nil {
		for _, arch := range fat.Arches {
			if arch.File.FileHeader.CPU == types.CPUAmd64 {
				end := uint64(arch.Offset) + uint64(arch.Size)
				if end > uint64(len(raw)) {
					return nil, nil, fmt.Errorf(
						"x86-64 slice runs past the end of the file (offset %d, size %d, file %d)",
						arch.Offset, arch.Size, len(raw))
				}
				return arch.File, raw[arch.Offset:end], nil
			}
		}

		names := make([]string, 0, len(fat.Arches))
		for _, arch := range fat.Arches {
			names = append(names, arch.File.FileHeader.CPU.String())
		}

		return nil, nil, fmt.Errorf(
			"universal binary has no x86-64 slice (has %v); the TCI build only interprets x86",
			names)
	}

	file, err := macho.NewFile(bytes.NewReader(raw))
	if err != nil {
		return nil, nil, err
	}

	if file.FileHeader.CPU != types.CPUAmd64 {
		return nil, nil, fmt.Errorf(
			"binary is %v, not x86-64; the TCI build only interprets x86",
			file.FileHeader.CPU)
	}

	return file, raw, nil
}

func build(file *macho.File, raw []byte) (*image, error) {
	out := &image{}

	for _, seg := range file.Segments() {
		name := seg.Name
		content := []byte(nil)
		if seg.Filesz > 0 && seg.Offset+seg.Filesz <= uint64(len(raw)) {
			content = append([]byte(nil), raw[seg.Offset:seg.Offset+seg.Filesz]...)
		}
		out.segments = append(out.segments, segment{
			name:    name,
			vmaddr:  seg.Addr,
			vmsize:  seg.Memsz,
			prot:    uint32(seg.Prot),
			content: content,
		})
	}

	// Imports get a stable slot index, so a bind only has to name a number.
	slotOf := map[string]int32{}
	for _, b := range mustBinds(file) {
		if _, ok := slotOf[b.Name]; ok {
			continue
		}
		slotOf[b.Name] = int32(len(out.imports))
		out.imports = append(out.imports, b.Name)
	}

	// Addends are counted before being trusted. The 10.9 binary reports zero
	// for every bind, while the macOS 27 one returns values in the hundreds of
	// millions, which are not plausible offsets and look like a misread of the
	// lazy-bind stream. Anything outside a sane range is dropped to zero and
	// counted, so the report shows whether that assumption held.
	for _, b := range mustBinds(file) {
		addend := int32(b.Addend)
		if addend > 0xffff || addend < -0xffff {
			addend = 0
			out.clampedAddends++
		}
		out.binds = append(out.binds, bind{
			addr:   b.Offset(),
			slot:   slotOf[b.Name],
			addend: addend,
		})
	}

	for _, r := range mustRebases(file) {
		out.rebases = append(out.rebases, r.Start+r.Offset)
	}

	// Module initialisers first. dyld would call these at load time, and the
	// first export tried (_WIn9UJ86JKdV4dM) returned after a single stack
	// probe, which is not what an entry point looks like. Whatever state the
	// library expects to exist before its API is usable is set up here.
	out.entries = append(out.entries, moduleInitialisers(file, raw)...)

	for _, name := range wantedEntries {
		if addr, err := file.FindSymbolAddress(name); err == nil {
			out.entries = append(out.entries, entry{name: name, addr: addr})
		}
	}

	sort.Slice(out.binds, func(i, j int) bool { return out.binds[i].addr < out.binds[j].addr })
	sort.Slice(out.rebases, func(i, j int) bool { return out.rebases[i] < out.rebases[j] })

	return out, nil
}

// moduleInitialisers reads __mod_init_func, the pointer array dyld walks after
// mapping a dylib. Each entry is a function the library wants run before any
// of its API is called.
func moduleInitialisers(file *macho.File, slice []byte) []entry {
	out := []entry{}
	for _, sec := range file.Sections {
		if sec.Name != "__mod_init_func" {
			continue
		}
		start := uint64(sec.Offset)
		end := start + sec.Size
		if end > uint64(len(slice)) {
			continue
		}
		data := slice[start:end]
		for i, n := 0, 0; i+8 <= len(data); i, n = i+8, n+1 {
			ptr := binary.LittleEndian.Uint64(data[i:])
			if ptr == 0 {
				continue
			}
			out = append(out, entry{name: fmt.Sprintf("modinit%d", n), addr: ptr})
		}
	}
	return out
}

func mustBinds(file *macho.File) types.Binds {
	binds, err := file.GetBindInfo()
	if err != nil {
		return nil
	}
	return binds
}

func mustRebases(file *macho.File) []types.Rebase {
	rebases, err := file.GetRebaseInfo()
	if err != nil {
		return nil
	}
	return rebases
}

func (im *image) reportSections(file *macho.File) {
	fmt.Printf("sections: %d\n", len(file.Sections))
	for _, sec := range file.Sections {
		if sec.Size == 0 {
			continue
		}
		fmt.Printf("  %-16s %-24s size=%d\n", sec.Seg, sec.Name, sec.Size)
	}
}

func (im *image) report() {
	fmt.Printf("segments: %d\n", len(im.segments))
	for _, s := range im.segments {
		fmt.Printf("  %-16s vmaddr=%#010x vmsize=%#010x prot=%d content=%d\n",
			s.name, s.vmaddr, s.vmsize, s.prot, len(s.content))
	}
	fmt.Printf("imports: %d\n", len(im.imports))
	for i, name := range im.imports {
		fmt.Printf("  [%2d] %s\n", i, name)
	}
	fmt.Printf("rebases: %d\n", len(im.rebases))
	for i, addr := range im.rebases {
		if i >= 10 {
			fmt.Printf("  ... %d more\n", len(im.rebases)-10)
			break
		}
		fmt.Printf("  %#x\n", addr)
	}
	fmt.Printf("binds: %d (addends clamped to 0: %d)\n", len(im.binds), im.clampedAddends)
	for i, b := range im.binds {
		if i >= 10 {
			fmt.Printf("  ... %d more\n", len(im.binds)-10)
			break
		}
		fmt.Printf("  %#x -> slot %d addend %d (%s)\n", b.addr, b.slot, b.addend, im.imports[b.slot])
	}
	// The bytes at each export are the cheapest possible sanity check on the
	// slice arithmetic: real code starts with 55 48 89 e5 or 48 83 ec, not
	// with something that decodes as an add into a wild pointer.
	fmt.Printf("entries: %d\n", len(im.entries))
	for _, e := range im.entries {
		fmt.Printf("  %-20s %#x  %s\n", e.name, e.addr, hexAt(im, e.addr, 8))
	}
}

func (im *image) encode() ([]byte, error) {
	buf := &bytes.Buffer{}

	buf.WriteString(magic)
	putU32(buf, version)
	putU32(buf, uint32(len(im.segments)))
	putU32(buf, uint32(len(im.imports)))
	putU32(buf, uint32(len(im.rebases)))
	putU32(buf, uint32(len(im.binds)))
	putU32(buf, uint32(len(im.entries)))

	for _, s := range im.segments {
		putName(buf, s.name, 16)
		putU64(buf, s.vmaddr)
		putU64(buf, s.vmsize)
		putU32(buf, s.prot)
		putU32(buf, uint32(len(s.content)))
	}
	for _, s := range im.segments {
		buf.Write(s.content)
	}

	for _, name := range im.imports {
		putName(buf, name, maxName)
	}
	for _, addr := range im.rebases {
		putU64(buf, addr)
	}
	for _, b := range im.binds {
		putU64(buf, b.addr)
		putU32(buf, uint32(b.slot))
		putU32(buf, uint32(b.addend))
	}
	for _, e := range im.entries {
		putName(buf, e.name, 32)
		putU64(buf, e.addr)
	}

	return buf.Bytes(), nil
}

// hexAt returns the first n bytes at a guest virtual address, so the report can
// show what the export actually points at.
func hexAt(im *image, addr uint64, n int) string {
	for _, s := range im.segments {
		if addr < s.vmaddr || addr >= s.vmaddr+s.vmsize {
			continue
		}
		off := addr - s.vmaddr
		end := off + uint64(n)
		if end > uint64(len(s.content)) {
			return "(beyond file content)"
		}
		return fmt.Sprintf("% x", s.content[off:end])
	}
	return "(not in any segment)"
}

func putU32(buf *bytes.Buffer, v uint32) { binary.Write(buf, binary.LittleEndian, v) }
func putU64(buf *bytes.Buffer, v uint64) { binary.Write(buf, binary.LittleEndian, v) }

func putName(buf *bytes.Buffer, name string, size int) {
	field := make([]byte, size)
	copy(field, name)
	buf.Write(field)
}
