package machimage

import (
	"encoding/binary"
	"testing"
)

// LDAPR is ARMv8.3-RCpc. The emulated CPU does not enable FEAT_LRCPC, so QEMU
// rejects it as unallocated and the SAP machine's signing path dies on the first
// one it meets in the shared cache. QEMU's own implementation of LDAPR is a full
// LDAR, so the rewrite is the same instruction with stronger ordering.
func TestStripRewritesLDAPR(t *testing.T) {
	cases := []struct {
		name  string
		input uint32
		want  uint32
	}{
		{"byte", 0x38bfc288, 0x08dffe88},
		{"half", 0x78bfc288, 0x48dffe88},
		{"word", 0xb8bfc288, 0x88dffe88},
		{"double", 0xf8bfc288, 0xc8dffe88},
	}

	for _, testCase := range cases {
		data := make([]byte, 4)
		binary.LittleEndian.PutUint32(data, testCase.input)

		if replaced := StripPAC(data); replaced != 1 {
			t.Fatalf("%s: replaced=%d, want 1", testCase.name, replaced)
		}

		if got := binary.LittleEndian.Uint32(data); got != testCase.want {
			t.Fatalf("%s: %#x -> %#x, want %#x", testCase.name, testCase.input, got, testCase.want)
		}
	}

	// A=0 is the release form (STLR), not LDAPR, and must be left alone.
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data, 0xf83fc288)

	if replaced := StripPAC(data); replaced != 0 {
		t.Fatalf("a non-LDAPR word was rewritten (replaced=%d)", replaced)
	}
}
