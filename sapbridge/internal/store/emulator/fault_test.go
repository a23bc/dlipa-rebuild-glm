package emulator

import "testing"

// The fault report only helps if the decode is right: a wrong base register
// prints a plausible address that belongs to nothing, which is worse than
// printing no address at all. Every case below is a word that actually appears
// in AppleMediaServices around the initWithBag fault.
func TestDecodeAccess(t *testing.T) {
	cases := []struct {
		name     string
		word     uint32
		register int
		offset   uint64
		ok       bool
	}{
		// ldr w8, [x16, #0x50] -- the instruction at 0x1a2a0621c, the fault site.
		{"ldr w8,[x16,#0x50]", 0xb9405208, 16, 0x50, true},
		// ldr x22, [x8] -- the caller's load at 0x1a2b4cdac.
		{"ldr x22,[x8]", 0xf9400116, 8, 0, true},
		// str x0, [x0] -- same family, store rather than load.
		{"str x0,[x0]", 0xf9000000, 0, 0, true},
		// ldrb w0, [x0] -- size 00, so imm12 is not scaled.
		{"ldrb w0,[x0]", 0x39400000, 0, 0, true},
		// ldr w8, [x16, #0x54] -- imm12 0x15 scaled by 4.
		{"ldr w8,[x16,#0x54]", 0xb9405608, 16, 0x54, true},

		// ldur x16, [x17, #-8] -- unscaled form, deliberately not covered:
		// decoding it as unsigned would produce +0x1f8 and point somewhere real
		// but wrong.
		{"ldur x16,[x17,#-8]", 0xf85f8e30, 0, 0, false},
		// mov x17, x1
		{"mov x17,x1", 0xaa0103f1, 0, 0, false},
		// b.eq +8
		{"b.eq", 0x54000040, 0, 0, false},
		// nop
		{"nop", 0xd503201f, 0, 0, false},
		// autib x16, x17
		{"autib", 0xdac11a30, 0, 0, false},
	}

	for _, c := range cases {
		register, offset, ok := decodeAccess(c.word)
		if ok != c.ok {
			t.Fatalf("%s: ok=%v, want %v", c.name, ok, c.ok)
		}

		if !ok {
			continue
		}

		if register != c.register || offset != c.offset {
			t.Fatalf("%s: got x%d+%#x, want x%d+%#x", c.name, register, offset, c.register, c.offset)
		}
	}
}

func TestRegisterOrdinal(t *testing.T) {
	cases := []struct {
		register int
		ordinal  int
		ok       bool
	}{
		{0, 199, true},
		{1, 200, true},
		{16, 215, true},
		{17, 216, true},
		{28, 227, true},
		{29, regX29, true},
		{30, regX30, true},
		{31, 0, false}, // xzr: reading it is meaningless for a fault report
		{-1, 0, false},
	}

	for _, c := range cases {
		ordinal, ok := registerOrdinal(c.register)
		if ok != c.ok {
			t.Fatalf("x%d: ok=%v, want %v", c.register, ok, c.ok)
		}

		if ok && ordinal != c.ordinal {
			t.Fatalf("x%d: ordinal %d, want %d", c.register, ordinal, c.ordinal)
		}
	}
}

// The three fixed regions are what makes a fault address classifiable without
// asking the engine for a region map.
func TestDescribeRegion(t *testing.T) {
	cases := []struct {
		address uint64
		want    string
	}{
		{heapBase, "heap"},
		{heapBase + heapSize - 1, "heap"},
		{heapBase + heapSize, "outside heap/stack/stub"},
		{stackBase, "stack"},
		// The x0 reported on device when initWithBag faulted.
		{0x5000007fee58, "stack"},
		{returnPC, "return stub"},
		{0x1a2a0621c, "outside heap/stack/stub"}, // AMS __text
	}

	for _, c := range cases {
		if got := describeRegion(c.address); got != c.want {
			t.Fatalf("%#x: got %q, want %q", c.address, got, c.want)
		}
	}
}

// TestDecodeRegisterAccess covers the register-offset form, which the immediate
// decoder reports nothing for.
//
// 0xb870698e is the instruction signing stopped on at 0x1a24c4d04:
// `ldr w14, [x12, x16]`. Without this decoder the log named neither the address
// nor the base register, and x12 was not even among the printed registers.
func TestDecodeRegisterAccess(t *testing.T) {
	cases := []struct {
		name     string
		word     uint32
		base     int
		index    int
		shift    uint
		unsigned bool
		ok       bool
	}{
		{"ldr w14,[x12,x16]", 0xb870698e, 12, 16, 0, false, true},
		// ldr x0, [x1, x2, lsl #3] -- S on a 64-bit access shifts by 3.
		{"ldr x0,[x1,x2,lsl#3]", 0xf8627820, 1, 2, 3, false, true},
		// ldr w0, [x1, x2, lsl #2] -- same, 32-bit access.
		{"ldr w0,[x1,x2,lsl#2]", 0xb8627820, 1, 2, 2, false, true},
		// ldr w0, [x1, w2, uxtw]
		{"ldr w0,[x1,w2,uxtw]", 0xb8624820, 1, 2, 0, true, true},

		// The immediate form must not be claimed here.
		{"ldr w8,[x16,#0x50]", 0xb9405208, 0, 0, 0, false, false},
		// Option 111 is SXTX, not covered.
		{"ldr w0,[x1,x2,sxtx#2]", 0xb862f820, 0, 0, 0, false, false},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			base, index, shift, unsigned, ok := decodeRegisterAccess(test.word)
			if ok != test.ok {
				t.Fatalf("%#x: ok=%v, want %v", test.word, ok, test.ok)
			}

			if !ok {
				return
			}

			if base != test.base || index != test.index || shift != test.shift || unsigned != test.unsigned {
				t.Fatalf("%#x: got x%d+x%d<<%d unsigned=%v, want x%d+x%d<<%d unsigned=%v",
					test.word, base, index, shift, unsigned, test.base, test.index, test.shift, test.unsigned)
			}
		})
	}
}
