package machimage

import (
	"encoding/binary"
	"testing"
)

// TestStripPACMasksAuthenticatedPointers pins what the PAC family becomes.
//
// Replacing AUT* with a NOP leaves a signed pointer signed, and the next load
// follows its top bits somewhere unmapped -- the fault that stopped the encoder
// at 0x1a2af0790. Zero-extending to 48 bits is the same pointer with the
// signature removed.
func TestStripPACMasksAuthenticatedPointers(t *testing.T) {
	cases := []struct {
		name   string
		before uint32
		after  uint32
	}{
		// The word that faulted, read out of AppleMediaServices at 0x1a2af078c.
		{"autda x16, x17", 0xdac11a30, 0xd340be10},
		{"pacia x16, x17", 0xdac10230, 0xd340be10},
		{"pacda x16, x17", 0xdac10a30, 0xd340be10},
		{"pacia x30, x30", 0xdac103de, 0xd340bfde},
	}

	for _, test := range cases {
		data := make([]byte, 4)
		binary.LittleEndian.PutUint32(data, test.before)

		if replaced := StripPAC(data); replaced != 1 {
			t.Fatalf("%s: replaced=%d, want 1", test.name, replaced)
		}

		if got := binary.LittleEndian.Uint32(data); got != test.after {
			t.Fatalf("%s: got %#x, want %#x", test.name, got, test.after)
		}
	}
}
