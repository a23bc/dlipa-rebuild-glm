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

// onIOS lists the install names that exist on iOS. Everything else becomes a
// weak link, because a weak dependency that is never called costs nothing
// while a strong one that is missing fails the whole load.
//
// The set is deliberately narrow: the dynamic call profile measured earlier
// showed the SAP paths touch about twenty symbols, all of them in libSystem,
// libdispatch or libobjc.
var onIOS = map[string]bool{
	"/usr/lib/libSystem.B.dylib":              true,
	"/usr/lib/libobjc.A.dylib":                true,
	"/usr/lib/libc++.1.dylib":                 true,
	"/usr/lib/libc++abi.dylib":                true,
	"/usr/lib/libsqlite3.dylib":               true,
	"/usr/lib/libz.1.dylib":                   true,
	"/usr/lib/libresolv.9.dylib":              true,
	"/usr/lib/libMobileGestalt.dylib":         true,
	"/usr/lib/libcompression.dylib":           true,
	"/usr/lib/system/libdispatch.dylib":       true,
	"/System/Library/Frameworks/Accelerate.framework/Accelerate":                 true,
	"/System/Library/Frameworks/Accounts.framework/Accounts":                     true,
	"/System/Library/Frameworks/CFNetwork.framework/CFNetwork":                   true,
	"/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation":         true,
	"/System/Library/Frameworks/CoreServices.framework/CoreServices":             true,
	"/System/Library/Frameworks/CoreText.framework/CoreText":                     true,
	"/System/Library/Frameworks/Foundation.framework/Foundation":                 true,
	"/System/Library/Frameworks/IOKit.framework/IOKit":                           true,
	"/System/Library/Frameworks/LocalAuthentication.framework/LocalAuthentication": true,
	"/System/Library/Frameworks/Network.framework/Network":                       true,
	"/System/Library/Frameworks/Security.framework/Security":                     true,
	"/System/Library/Frameworks/UniformTypeIdentifiers.framework/UniformTypeIdentifiers": true,
	"/System/Library/Frameworks/UserNotifications.framework/UserNotifications":   true,
}

// swiftOnIOS matches the Swift runtime libraries, which ship on iOS under
// /usr/lib/swift and are numerous enough to match by prefix.
var swiftPrefixes = []string{
	"/usr/lib/swift/",
	"/usr/lib/system/",
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

	file, err := openThin(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}

	report(file)

	install := *name
	if install == "" {
		install = "@rpath/" + baseName(*out)
	}

	converted, err := convert(data, file, install)
	if err != nil {
		fmt.Fprintf(os.Stderr, "convert: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(*out, converted, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write %s: %v\n", *out, err)
		os.Exit(1)
	}

	fmt.Printf("==> wrote %s (%d bytes)\n", *out, len(converted))
}

func openThin(data []byte) (*macho.File, error) {
	if fat, err := macho.NewFatFile(bytes.NewReader(data)); err == nil {
		for _, arch := range fat.Arches {
			if arch.File.FileHeader.CPU == types.CPUArm64 {
				return arch.File, nil
			}
		}

		return nil, fmt.Errorf("universal binary has no arm64 slice (%d present)", len(fat.Arches))
	}

	return macho.NewFile(bytes.NewReader(data))
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
				stripPAC(out, binary.LittleEndian.Uint64(out[offset+24:]),
					binary.LittleEndian.Uint64(out[offset+32:]))
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
		// Append after the existing commands and fix up the header.
		sizeofcmds := int(binary.LittleEndian.Uint32(out[20:]))
		out = append(out, extra...)
		binary.LittleEndian.PutUint32(out[16:], uint32(ncmds+2))
		binary.LittleEndian.PutUint32(out[20:], uint32(sizeofcmds+len(extra)))
	}

	return out, nil
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

func availableOnIOS(path string) bool {
	if onIOS[path] {
		return true
	}

	for _, prefix := range swiftPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}

	return false
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
