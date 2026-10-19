// Command prepareasset rewrites one pinned macOS binary into a form iOS dyld
// will load.
//
// ## What the device established
//
// A matrix of 1 KB dylibs settled every constraint before this was written:
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
// It leaves the fixup chains alone. That is the next step and it is not
// small: the chains are encoded as arm64e and the subtype change invalidates
// them. Shipping this first is deliberate - it puts the cheapest possible
// question to the device, and dyld's error for the not-yet-converted chains
// tells us what the conversion has to produce.
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

	lcSegment64       = 0x19
	lcIDDylib         = 0x0d
	lcLoadDylib       = 0x0c
	lcLoadWeakDylib   = 0x80000018
	lcBuildVersion    = 0x32
	lcVersionMinMacosx = 0x24

	lcSymtab                = 0x02
	lcDysymtab              = 0x0b
	lcDyldInfo              = 0x22
	lcDyldInfoOnly          = 0x80000022
	lcCodeSignature         = 0x1d
	lcSegmentSplitInfo      = 0x1e
	lcFunctionStarts        = 0x26
	lcDataInCode            = 0x29
	lcDylibCodeSignDRs      = 0x2b
	lcLinkerOptimizationHint = 0x2e
	lcEncryptionInfo64      = 0x2c
	lcDyldExportsTrie       = 0x8000001f
	lcDyldChainedFixups     = 0x80000034

	platformIOS = 0x2

	// iOS 15.0, as dyld packs it: major in the high half, minor and patch in
	// the low bytes.
	ios15 = 0x000F0000

	// CPU_SUBTYPE_ARM64_ALL. Writing 0 also drops the 0x80000000 capability
	// bit that marks the arm64e PTRAUTH ABI, which is the part dyld rejects.
	subtypeARM64All = 0x0

	// NOP.
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

// swiftPrefixes matches the Swift runtime and the libsystem sublibraries,
// which ship on iOS under these directories and are numerous enough to match
// by prefix rather than enumerate.
var swiftPrefixes = []string{
	"/usr/lib/swift/",
	"/usr/lib/system/",
}

func availableOnIOS(path string) bool {
	for _, prefix := range swiftPrefixes {
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

	// Re-parse the result before writing it. The bug this catches is real and
	// was shipped once: appending a load command to the end of the file
	// instead of to the end of the command region produced a file that dyld
	// rejected with "malformed load command ... size (0x0) too small", and
	// nothing noticed until it was on a device.
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

// verify re-reads the converted image and walks its load commands, which is
// the same walk dyld does.
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

	fmt.Printf("    verified: %d commands, %d bytes, type %v, subtype %v\n",
		seen, sizeofcmds, file.FileHeader.Type, file.FileHeader.SubCPU)

	return nil
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

			start := arch.Offset
			end := arch.Offset + arch.Size
			if uint64(len(data)) < uint64(end) {
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
			fmt.Printf("    LC_VERSION_MIN_MACOSX (no build version)\n")
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

	headerSize := 32
	ncmds := int(binary.LittleEndian.Uint32(out[16:]))
	offset := headerSize
	hasBuildVersion := false
	hasID := false

	extra := []byte{}

	for i := 0; i < ncmds; i++ {
		cmd := binary.LittleEndian.Uint32(out[offset:])
		size := int(binary.LittleEndian.Uint32(out[offset+4:]))

		switch cmd {
		case lcSegment64:
			if name := segmentName(out, offset); name == "__TEXT" {
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
		case lcVersionMinMacosx:
			// No LC_BUILD_VERSION to patch; one is appended below.
			fmt.Printf("    LC_VERSION_MIN_MACOSX present, appending LC_BUILD_VERSION\n")
		case lcIDDylib:
			hasID = true
		case lcLoadDylib:
			// 4. Weakly link anything iOS does not have.
			path := dylibName(out, offset)
			if !availableOnIOS(path) {
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
		out = insertCommands(out, offset, extra)
	}

	return out, nil
}

// insertCommands splices new load commands in at the end of the command
// region and shifts every file offset in the existing commands to match.
//
// Appending to the end of the file - which is what the first version did -
// leaves the commands non-contiguous with the header. dyld walks them
// sequentially from offset 32, so it reads past the last real command
// straight into segment data and reports
// "malformed load command #N ... size (0x0) too small".
func insertCommands(data []byte, commandsEnd int, extra []byte) []byte {
	delta := uint64(len(extra))

	out := make([]byte, 0, len(data)+len(extra))
	out = append(out, data[:commandsEnd]...)
	out = append(out, extra...)
	out = append(out, data[commandsEnd:]...)

	shiftFileOffsets(out, delta)

	ncmds := binary.LittleEndian.Uint32(out[16:])
	sizeofcmds := binary.LittleEndian.Uint32(out[20:])
	binary.LittleEndian.PutUint32(out[16:], ncmds+uint32(countCommands(extra)))
	binary.LittleEndian.PutUint32(out[20:], sizeofcmds+uint32(len(extra)))

	return out
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

// File-offset fields that must move when the command region grows.
//
// Indices are byte offsets from the start of each load command. Only
// commands that actually carry file offsets are listed; a command that is
// not listed here has none, or only holds counts and indices.
var offsetFields = map[uint32][]int{
	lcSegment64: {40},            // fileoff
	lcSymtab:    {8, 16},         // symoff, stroff
	lcDysymtab:  {32, 40, 48, 56, 64, 72},
	lcDyldInfo:  {8, 16, 24, 32, 40},
	lcDyldInfoOnly: {8, 16, 24, 32, 40},
}

// Commands with a single dataoff at +8: everything in the linkedit family.
var dataoffCommands = []uint32{
	lcCodeSignature, lcSegmentSplitInfo, lcFunctionStarts, lcDataInCode,
	lcDylibCodeSignDRs, lcLinkerOptimizationHint, lcDyldExportsTrie,
	lcDyldChainedFixups, lcEncryptionInfo64,
}

func shiftFileOffsets(data []byte, delta uint64) {
	ncmds := int(binary.LittleEndian.Uint32(data[16:]))
	offset := 32

	for i := 0; i < ncmds; i++ {
		if offset+8 > len(data) {
			return
		}

		cmd := binary.LittleEndian.Uint32(data[offset:])
		size := int(binary.LittleEndian.Uint32(data[offset+4:]))
		if size <= 0 || offset+size > len(data) {
			return
		}

		fields := offsetFields[cmd]
		for _, base := range fields {
			bumpOffset(data, offset+base, delta)
		}

		for _, candidate := range dataoffCommands {
			if cmd == candidate {
				bumpOffset(data, offset+8, delta)
			}
		}

		offset += size
	}
}

func bumpOffset(data []byte, at int, delta uint64) {
	if at+8 > len(data) {
		return
	}

	value := binary.LittleEndian.Uint64(data[at:])
	if value == 0 {
		return
	}

	binary.LittleEndian.PutUint64(data[at:], value+delta)
}

func segmentName(data []byte, offset int) string {
	end := offset + 24
	name := strings.TrimRight(string(data[offset+8:end]), "\x00")

	return name
}

func dylibName(data []byte, offset int) string {
	nameOffset := int(binary.LittleEndian.Uint32(data[offset+8:]))
	start := offset + nameOffset
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
	// cmd, cmdsize, platform, minos, sdk, ntools
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

// stripPAC rewrites pointer-authentication instructions inside an executable
// range. The A10 in the target device has no PAC, so these would be undefined.
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
