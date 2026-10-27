package machimage

import (
	"bytes"
	"fmt"
	"os"
	"testing"

	"github.com/blacktop/go-macho"
)

// The guest-side re-strip in store/emulator can only fix PAC instructions that
// fall inside a range TextSections reported. Two ways that silently stops
// working, both seen in this project:
//
//   - Load() nils i.file, so reading the section table afterwards yields no
//     ranges at all and the re-strip loops over nothing (the panic at
//     image.go:711 was this, caught one call too late);
//   - widening or narrowing the flag filter moves the range off the code.
//
// Both leave the build compiling and the device still crashing, so assert the
// ranges here instead.
const (
	amsAsset       = "../../../../VendorAssets/AppleMediaServices"
	amsFaultAddr   = 0x1a2af078c // AUTIB x16, x17 -- where E1-b stopped
	amsStripBudget = 1000        // device log saw 11221 replacements

	// The 0x1a241d000+0xa80000 in the old device log is the __TEXT *segment*,
	// from the build that walked the segment instead of its sections. The
	// instruction sections themselves start later and are narrower, so the test
	// takes them from the file rather than from that log line.
)

func loadAMS(t *testing.T) (*Image, []byte) {
	t.Helper()

	raw, err := os.ReadFile(amsAsset)
	if err != nil {
		t.Skipf("asset not present: %v", err)
	}

	image, err := Open("AppleMediaServices", raw)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	err = image.PreparePrelinked(nil, func(symbol string) (uint64, error) {
		return 0, fmt.Errorf("unexpected relocation %s", symbol)
	})
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}

	return image, raw
}

// TestTextSectionsCoverTheFaultAddress is the regression guard for reading the
// section table after Load freed the image: that version returned zero ranges,
// and every later assertion here would have failed on it.
func TestTextSectionsCoverTheFaultAddress(t *testing.T) {
	image, _ := loadAMS(t)

	sections := image.TextSections()
	if len(sections) == 0 {
		t.Fatal("no instruction sections: the guest re-strip would walk nothing")
	}

	var total uint64

	covered := false

	for _, section := range sections {
		start, size := section[0], section[1]
		total += size

		if amsFaultAddr >= start && amsFaultAddr < start+size {
			covered = true

			t.Logf("fault %#x inside %#x+%#x", amsFaultAddr, start, size)
		}
	}

	if !covered {
		t.Fatalf("fault address %#x is outside every reported range", amsFaultAddr)
	}

	// Thousands of instructions, not a handful: the filter must select the real
	// code sections and nothing else.
	if total < 1<<20 {
		t.Fatalf("sections cover only %d bytes, expected megabytes of code", total)
	}

	t.Logf("%d sections, %d bytes total", len(sections), total)
}

// TestStripPACRewritesTheRawText is what the guest re-strip depends on: the
// profile pages are a snapshot of the original process, so they hand back the
// unstripped bytes. If StripPAC finds nothing to do on those, the re-strip is
// decorative.
func TestStripPACRewritesTheRawText(t *testing.T) {
	_, raw := loadAMS(t)

	data, err := arm64Slice(raw)
	if err != nil {
		t.Fatalf("slice: %v", err)
	}

	file, err := macho.NewFile(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// Read the sections straight out of the file, before Open stripped them.
	var total, sections int

	for _, section := range file.Sections {
		if !section.Flags.IsPureInstructions() {
			continue
		}

		end := uint64(section.Offset) + section.Size
		if end > uint64(len(data)) {
			t.Fatalf("section %s exceeds file", section.Name)
		}

		replaced := StripPAC(data[section.Offset:end])
		total += replaced
		sections++

		t.Logf("%-14s %#x+%#x: %d replaced", section.Name, section.Addr, section.Size, replaced)
	}

	if sections == 0 {
		t.Fatal("no instruction sections in the file")
	}

	if total < amsStripBudget {
		t.Fatalf("StripPAC replaced %d instructions across %d sections, expected thousands", total, sections)
	}

	t.Logf("StripPAC replaced %d instructions across %d sections", total, sections)
}
