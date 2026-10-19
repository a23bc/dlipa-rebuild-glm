// Command prepareasset rewrites one pinned macOS binary into a form iOS dyld
// will load.
//
// ## What the device established
//
// A matrix of 1 KB dylibs settled the constraints before this was written:
//
//	ios-classic     dlopen=OK
//	ios-chained     dlopen=OK           chained fixups are accepted
//	ios-arm64e      dlopen=FAIL         incompatible architecture (have (arm64e), need (arm64))
//	macos-classic   dlopen=FAIL         incompatible platform (have (macOS), need (iOS))
//	macos-chained   dlopen=FAIL         incompatible platform (have (macOS), need (iOS))
//
// So the platform must become iOS and the CPU subtype must become plain
// arm64. Both are hard rejections with their own error text. Chained fixups
// are not the obstacle.
//
// commerce itself confirmed the first two on a real device: after
// conversion it no longer complains about platform or architecture, only
// about what comes next.
//
// ## What this does
//
//	1. CPU subtype  arm64e -> arm64 (clears the PTRAUTH capability bit too)
//	2. file type    MH_EXECUTE -> MH_DYLIB
//	3. platform     macOS -> iOS, with a 15.0 minimum
//	4. dependencies keep only what iOS has; weakly link the rest
//	5. LC_ID_DYLIB  added if absent, so the three can reference each other
//	6. __TEXT       strip pointer-authentication instructions
//
// ## What it deliberately does not do yet
//
// It leaves the fixup chains alone. They are encoded as arm64e and the
// subtype change invalidates them, but converting them is the expensive
// part, and dyld's complaint about the unconverted chains is what should
// decide what the conversion has to produce.
//
// The assets are not in this repository. Run it where they are:
//
//	prepareasset -in <asset> -out <dylib>
package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
)

const (
	mhExecute = 0x2
	mhDylib   = 0x6

	lcSegment64        = 0x19
	lcIDDylib          = 0x0d
	lcLoadDylib        = 0x0c
	lcLoadWeakDylib    = 0x80000018
	lcBuildVersion     = 0x32
	lcVersionMinMacosx = 0x24

	platformIOS = 0x2

	// iOS 15.0, as dyld packs it: major in the high half.
	ios15 = 0x000F0000

	// CPU_SUBTYPE_ARM64_ALL. Writing 0 also drops the 0x80000000 capability
	// bit that marks the arm64e PTRAUTH ABI, which is the part dyld rejects.
	subtypeARM64All = 0x0

	// arm64 page size. dyld mmaps each segment at its file offset, and mmap
	// requires that offset to be a multiple of this.
	pageSize = 0x4000

	nop = 0xd503201f
)

// frameworkOnIOS and libOnIOS are matched by name, not by full path,
// because the same framework sits at a different path on each platform:
// macOS uses /Versions/A/..., iOS often /Versions/C/... or none at all.
// Matching the whole path silently weakened Foundation, CoreFoundation,
// IOKit and Security in the first run.
var frameworkOnIOS = map[string]bool{
	"Accelerate.framework":             true,
	"Accounts.framework":               true,
	"CFNetwork.framework":              true,
	"CoreFoundation.framework":         true,
	"CoreServices.framework":           true,
	"CoreText.framework":               true,
	"CryptoKit.framework":              true,
	"Foundation.framework":             true,
	"IOKit.framework":                  true,
	"LocalAuthentication.framework":    true,
	"Network.framework":                true,
	"Security.framework":               true,
	"UniformTypeIdentifiers.framework": true,
	"UserNotifications.framework":      true,
}

var libOnIOS = map[string]bool{
	"libSystem.B.dylib":      true,
	"libobjc.A.dylib":        true,
	"libc++.1.dylib":         true,
	"libc++abi.dylib":        true,
	"libsqlite3.dylib":       true,
	"libz.1.dylib":           true,
	"libresolv.9.dylib":      true,
	"libMobileGestalt.dylib": true,
	"libcompression.dylib":   true,
}

// libPrefixesOnIOS matches the Swift runtime and the libsystem
// sublibraries, which ship on iOS under these directories and are numerous
// enough to match by prefix rather than enumerate.
var libPrefixesOnIOS = []string{
	"/usr/lib/swift/",
	"/usr/lib/system/",
}

func availableOnIOS(path string) bool {
	for _, prefix := range libPrefixesOnIOS {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}

	if i := strings.Index(path, ".framework"); i >= 0 {
		name := path[:i+len(".framework")]
		if j := strings.LastIndex(name, "/"); j >= 0 {
			name = name[j+1:]
		}

		return frameworkOnIOS[name]
	}

	return libOnIOS[baseName(path)]
}

func main() {
	in := flag.String("in", "", "input macOS binary")
	out := flag.String("out", "", "output dylib")
	name := flag.String("name", "", "install name to record in LC_ID_DYLIB")
	flag.Parse()

	if *in == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "usage: prepareasset -in <asset> -out <dylib> [-name <install-name>]")
		os.Exit(2)
	}

	data, err := os.ReadFile(*in)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read %s: %v\n", *in, err)
		os.Exit(1)
	}

	file, slice, err := openThin(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}

	report(file)

	install := *name
	if install == "" {
		install = "@rpath/" + baseName(*out)
	}

	// Operate on the slice, never on the original buffer. These assets are
	// universal binaries, so the Mach-O header is not at offset 0 - editing
	// offset 0 would rewrite the fat header and produce nonsense.
	converted, err := convert(slice, file, install)
	if err != nil {
		fmt.Fprintf(os.Stderr, "convert: %v\n", err)
		os.Exit(1)
	}

	// Re-parse and re-walk the result before writing it. Two structural bugs
	// reached a device before this existed, and both were visible here.
	if err := verify(converted); err != nil {
		fmt.Fprintf(os.Stderr, "converted output does not parse: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(*out, converted, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write %s: %v\n", *out, err)
		os.Exit(1)
	}

	fmt.Printf("==> wrote %s (%d bytes)\n", *out, len(converted))
}

// openThin returns the arm64 slice and just its bytes. Writing a thin file
// keeps every offset below relative to the Mach-O header, which is what the
// conversions assume.
func openThin(data []byte) (*macho.File, []byte, error) {
	if fat, err := macho.NewFatFile(bytes.NewReader(data)); err == nil {
		for _, arch := range fat.Arches {
			if arch.File.FileHeader.CPU != types.CPUArm64 {
				continue
			}

			start := int(arch.Offset)
			end := start + int(arch.Size)
			if end > len(data) {
				return nil, nil, fmt.Errorf("arch slice %#x..%#x exceeds the file", start, end)
			}

			slice := make([]byte, arch.Size)
			copy(slice, data[start:end])

			return arch.File, slice, nil
		}

		return nil, nil, fmt.Errorf("universal binary has no arm64 slice (%d present)", len(fat.Arches))
	}

	file, err := macho.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, nil, err
	}

	slice := make([]byte, len(data))
	copy(slice, data)

	return file, slice, nil
}

func baseName(path string) string {
	if i := strings.LastIndexAny(path, `/\\`); i >= 0 {
		return path[i+1:]
	}

	return path
}

func report(file *macho.File) {
	fmt.Printf("    cpu %v subtype %v type %v\n",
		file.FileHeader.CPU, file.FileHeader.SubCPU, file.FileHeader.Type)

	for _, load := range file.Loads {
		switch typed := load.(type) {
		case *macho.BuildVersion:
			fmt.Printf("    LC_BUILD_VERSION platform=%d\n", typed.Platform)
		case *macho.VersionMinMacOSX:
			fmt.Printf("    LC_VERSION_MIN_MACOSX present, no build version to patch\n")
		case *macho.LoadDylib:
			fmt.Printf("    dep %s\n", typed.Name)
		}
	}
}

func convert(data []byte, file *macho.File, install string) ([]byte, error) {
	out := make([]byte, len(data))
	copy(out, data)

	// 1. CPU subtype: arm64e -> arm64. This also clears the PTRAUTH capability
	// bit, which is the part dyld names in its rejection.
	binary.LittleEndian.PutUint32(out[8:], subtypeARM64All)

	// 2. File type: MH_EXECUTE -> MH_DYLIB.
	if fileType := binary.LittleEndian.Uint32(out[12:]); fileType == mhExecute {
		binary.LittleEndian.PutUint32(out[12:], mhDylib)
		fmt.Printf("    filetype %d -> MH_DYLIB\n", fileType)
	}

	ncmds := int(binary.LittleEndian.Uint32(out[16:]))
	sizeofcmds := int(binary.LittleEndian.Uint32(out[20:]))
	offset := 32
	hasBuildVersion := false
	hasID := false
	extra := []byte{}

	for i := 0; i < ncmds; i++ {
		cmd := binary.LittleEndian.Uint32(out[offset:])
		size := int(binary.LittleEndian.Uint32(out[offset+4:]))

		switch cmd {
		case lcSegment64:
			if segmentName(out, offset) == "__TEXT" {
				// LC_SEGMENT_64: segname(8) vmaddr(24) vmsize(32)
				// fileoff(40) filesize(48). The first two are virtual, and
				// using them here walks off the end of the file.
				stripPAC(out, binary.LittleEndian.Uint64(out[offset+40:]),
					binary.LittleEndian.Uint64(out[offset+48:]))
			}
		case lcBuildVersion:
			// 3. platform macOS -> iOS.
			hasBuildVersion = true
			binary.LittleEndian.PutUint32(out[offset+8:], platformIOS)
			binary.LittleEndian.PutUint32(out[offset+12:], ios15)
			binary.LittleEndian.PutUint32(out[offset+16:], ios15)
			fmt.Printf("    LC_BUILD_VERSION -> platform=iOS minos=sdk 15.0\n")
		case lcIDDylib:
			hasID = true
		case lcLoadDylib:
			// 4. Weakly link anything iOS does not have.
			if path := dylibName(out, offset); !availableOnIOS(path) {
				binary.LittleEndian.PutUint32(out[offset:], lcLoadWeakDylib)
				fmt.Printf("    weak: %s\n", path)
			}
		}

		offset += size
	}

	// 3b. A shared-cache slice often carries no LC_BUILD_VERSION at all.
	if !hasBuildVersion {
		extra = append(extra, buildVersionCommand()...)
	}

	// 5. LC_ID_DYLIB so the three can reference each other.
	if !hasID {
		extra = append(extra, idDylibCommand(install)...)
		fmt.Printf("    added LC_ID_DYLIB %s\n", install)
	}

	if len(extra) > 0 {
		// Place the new commands in the padding between the end of the load
		// commands and the first section. Nothing moves, so no file offset
		// needs adjusting.
		//
		// Making room by shifting the file - what an earlier version did -
		// breaks the page alignment of every following segment's file
		// offset, and dyld's mmap of that segment then fails with EINVAL.
		// That is what the device reported.
		room := unusedSlack(file, offset)
		if room < len(extra) {
			return nil, fmt.Errorf(
				"need %d bytes for new load commands, only %d free after them; "+
					"refusing to shift the file and break page alignment",
				len(extra), room)
		}

		copy(out[offset:offset+len(extra)], extra)
		binary.LittleEndian.PutUint32(out[16:], uint32(ncmds+countCommands(extra)))
		binary.LittleEndian.PutUint32(out[20:], uint32(sizeofcmds+len(extra)))
		fmt.Printf("    placed %d bytes of new commands in %d bytes of padding\n",
			len(extra), room)
	}

	return out, nil
}

// unusedSlack reports how many bytes between the end of the load commands
// and the first section are not referenced by anything. That gap is padding
// - usually because sections start at page-aligned offsets - so it is safe
// to write into.
func unusedSlack(file *macho.File, commandsEnd int) int {
	lowest := -1

	for _, section := range file.Sections {
		if section.Offset == 0 {
			continue
		}
		if lowest < 0 || int(section.Offset) < lowest {
			lowest = int(section.Offset)
		}
	}

	if lowest <= commandsEnd {
		return 0
	}

	return lowest - commandsEnd
}

func countCommands(commands []byte) int {
	count := 0

	for at := 0; at+8 <= len(commands); {
		size := int(binary.LittleEndian.Uint32(commands[at+4:]))
		if size <= 0 {
			break
		}
		count++
		at += size
	}

	return count
}

func segmentName(data []byte, offset int) string {
	return strings.TrimRight(string(data[offset+8:offset+24]), "\x00")
}

func dylibName(data []byte, offset int) string {
	start := offset + int(binary.LittleEndian.Uint32(data[offset+8:]))
	if start >= len(data) {
		return ""
	}
	if end := bytes.IndexByte(data[start:], 0); end >= 0 {
		return string(data[start : start+end])
	}

	return string(data[start:])
}

func buildVersionCommand() []byte {
	buf := new(bytes.Buffer)
	for _, v := range []uint32{lcBuildVersion, 24, platformIOS, ios15, ios15, 0} {
		_ = binary.Write(buf, binary.LittleEndian, v)
	}

	return buf.Bytes()
}

func idDylibCommand(install string) []byte {
	name := append([]byte(install), 0)
	for len(name)%8 != 0 {
		name = append(name, 0)
	}

	buf := new(bytes.Buffer)
	for _, v := range []uint32{lcIDDylib, uint32(24 + len(name)), 24, 0, 0x10000, 0x10000} {
		_ = binary.Write(buf, binary.LittleEndian, v)
	}
	buf.Write(name)

	return buf.Bytes()
}

// stripPAC rewrites pointer-authentication instructions inside an
// executable range. The A10 in the target device has no PAC, so these would
// be undefined.
//
// Ported from scripts/prepare-commerce.py, which already did this for
// commerce. Branches and returns keep their meaning and lose only the
// authentication; everything else in the PAC space becomes a NOP.
func stripPAC(data []byte, fileOffset, fileSize uint64) {
	if fileOffset+fileSize > uint64(len(data)) {
		fmt.Printf("    __TEXT range exceeds the file; skipped\n")

		return
	}

	changed := 0

	for at := fileOffset; at+4 <= fileOffset+fileSize; at += 4 {
		word := binary.LittleEndian.Uint32(data[at:])

		if replacement := stripOne(word); replacement != word {
			binary.LittleEndian.PutUint32(data[at:], replacement)
			changed++
		}
	}

	fmt.Printf("    __TEXT: %d PAC instructions rewritten\n", changed)
}

func stripOne(word uint32) uint32 {
	// BRAA / BRAAZ -> BR
	if word&0xfffffc1f == 0xd61f0800 || word&0xfffffc1f == 0xd61f081f {
		return 0xd61f0000 | ((word >> 5) & 0x1f << 5)
	}
	// BLRAA / BLRAAZ -> BLR
	if word&0xfffffc1f == 0xd63f0800 || word&0xfffffc1f == 0xd63f081f {
		return 0xd63f0000 | ((word >> 5) & 0x1f << 5)
	}
	// RETAB -> RET
	if word == 0xd65f0fff {
		return 0xd65f03c0
	}

	if isPAC(word) {
		return nop
	}

	return word
}

func isPAC(word uint32) bool {
	if word&0xfffffc00 == 0xd5032100 {
		return true
	}
	if word&0xffe0fc00 == 0xdac00000 {
		return true
	}
	if word&0xffe0fc00 == 0xdac00400 {
		return true
	}
	if word&0xff000000 == 0xda000000 {
		switch (word >> 12) & 0xff {
		case 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
			0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
			0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
			0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d:
			return true
		}
	}

	return false
}

// verify re-reads the converted image and walks its load commands, which is
// the same walk dyld does. It also checks the one invariant that broke
// silently: dyld mmaps each segment at its file offset, and mmap requires
// that offset to be page aligned.
func verify(data []byte) error {
	file, err := macho.NewFile(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("open converted image: %w", err)
	}

	ncmds := binary.LittleEndian.Uint32(data[16:])
	sizeofcmds := binary.LittleEndian.Uint32(data[20:])
	if uint64(32+sizeofcmds) > uint64(len(data)) {
		return fmt.Errorf("sizeofcmds %d exceeds the %d byte file", sizeofcmds, len(data))
	}

	offset := 32
	seen := 0

	for i := uint32(0); i < ncmds; i++ {
		if offset+8 > len(data) {
			return fmt.Errorf("load command %d starts past the end of the file", i)
		}

		size := int(binary.LittleEndian.Uint32(data[offset+4:]))
		if size < 8 || offset+size > len(data) {
			return fmt.Errorf("load command %d has size %d at %d, past the %d byte file",
				i, size, offset, len(data))
		}

		offset += size
		seen++
	}

	for _, load := range file.Loads {
		segment, ok := load.(*macho.Segment)
		if !ok {
			continue
		}

		if segment.Offset%pageSize != 0 {
			return fmt.Errorf("segment %s file offset %#x is not %#x aligned; dyld's mmap will fail with EINVAL",
				segment.Name, segment.Offset, pageSize)
		}

		if uint64(segment.Offset+segment.Filesz) > uint64(len(data)) {
			return fmt.Errorf("segment %s spans %#x..%#x past the %d byte file",
				segment.Name, segment.Offset, segment.Offset+segment.Filesz, len(data))
		}
	}

	fmt.Printf("    verified: %d commands, %d bytes, type %v, subtype %v\n",
		seen, sizeofcmds, file.FileHeader.Type, file.FileHeader.SubCPU)

	return nil
}
