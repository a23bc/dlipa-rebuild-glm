package machine

import "testing"

// TestClassifyAtomic covers every encoding the ARM manual gives for the two LSE
// shapes the compatibility layer emulates.
//
// The point is the ordering bits: CAS puts acquire at bit 22 and release at bit
// 15, SWP puts them at 23 and 22, and both sit inside the opcode. Recognising
// only the *al forms is what stopped signing on casa x8, x9, [x0] -- which is
// 0xc8e87c09, the one non-*al encoding actually observed on the device.
//
// Capstone 5.0.7 produced the mnemonics below from these words.
func TestClassifyAtomic(t *testing.T) {
	cases := []struct {
		name     string
		word     uint32
		mnemonic string
		width    uint64
		isCAS    bool
	}{
		{"cas w", 0x88a07c00, "cas w0, w0, [x0]", 4, true},
		{"casa w", 0x88e07c00, "casa w0, w0, [x0]", 4, true},
		{"casl w", 0x88a0fc00, "casl w0, w0, [x0]", 4, true},
		{"casal w", 0x88e0fc00, "casal w0, w0, [x0]", 4, true},
		{"cas x", 0xc8a07c00, "cas x0, x0, [x0]", 8, true},
		{"casa x", 0xc8e07c00, "casa x0, x0, [x0]", 8, true},
		{"casl x", 0xc8a0fc00, "casl x0, x0, [x0]", 8, true},
		{"casal x", 0xc8e0fc00, "casal x0, x0, [x0]", 8, true},
		{"the observed fault", 0xc8e87c09, "casa x8, x9, [x0]", 8, true},
		{"swp w", 0xb8208000, "swp w0, w0, [x0]", 4, false},
		{"swpa w", 0xb8a08000, "swpa w0, w0, [x0]", 4, false},
		{"swpl w", 0xb8608000, "swpl w0, w0, [x0]", 4, false},
		{"swpal w", 0xb8e08000, "swpal w0, w0, [x0]", 4, false},
		{"swp x", 0xf8208000, "swp x0, x0, [x0]", 8, false},
		{"swpa x", 0xf8a08000, "swpa x0, x0, [x0]", 8, false},
		{"swpl x", 0xf8608000, "swpl x0, x0, [x0]", 8, false},
		{"swpal x", 0xf8e08000, "swpal x0, x0, [x0]", 8, false},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			width, isCAS, ok := classifyAtomic(test.word)
			if !ok {
				t.Fatalf("%#x (%s) is not recognised", test.word, test.mnemonic)
			}
			if width != test.width {
				t.Fatalf("%#x (%s): width %d, want %d", test.word, test.mnemonic, width, test.width)
			}
			if isCAS != test.isCAS {
				t.Fatalf("%#x (%s): isCAS %v, want %v", test.word, test.mnemonic, isCAS, test.isCAS)
			}
		})
	}
}

// TestClassifyAtomicRejectsOrdinaryCode keeps the masks from claiming loads and
// vector ops, which are the neighbouring encodings.
func TestClassifyAtomicRejectsOrdinaryCode(t *testing.T) {
	for _, word := range []uint32{
		0xf9400230, // ldr x16, [x17]
		0xf9400d23, // ldr x3, [x9, #0x18]
		0xce000000, // eor3 -- handled before this, but must not look atomic
		0xd503201f, // nop
	} {
		if _, _, ok := classifyAtomic(word); ok {
			t.Fatalf("%#x was classified as an LSE atomic", word)
		}
	}
}

// TestIsSVC pins the encoding the compatibility layer looks for. The comm page's
// fallback is `mov w16, #-3; svc #0x80; ret`, so both the svc and the ret that
// follows it have to be recognised for the look-back to work.
func TestIsSVC(t *testing.T) {
	if !isSVC(0xd4001001) { // svc #0x80
		t.Fatal("svc #0x80 not recognised")
	}

	if !isSVC(0xd4000001) { // svc #0
		t.Fatal("svc #0 not recognised")
	}

	for _, word := range []uint32{
		0xd65f03c0, // ret
		0xd4001002, // not an svc: bit 0 clear
		0xf9400230, // ldr x16, [x17]
	} {
		if isSVC(word) {
			t.Fatalf("%#x was classified as an svc", word)
		}
	}

	if arm64RET != 0xd65f03c0 {
		t.Fatalf("arm64RET is %#x", arm64RET)
	}
}

// TestEndsTrapStub pins the shapes that follow an inline trap.
//
// 0x54000103 is the word the device stopped on: `b.lo`, the carry check after
// `mov x16, #0x74; svc #0x80`. Looking only for `ret` was the mistake that cost
// the round before it.
func TestEndsTrapStub(t *testing.T) {
	for _, word := range []uint32{
		0x54000103, // b.lo -- the observed one
		0x54000040, // b.eq
		0xd65f03c0, // ret
		0x14000010, // b
		0x34000040, // cbz
		0x36000040, // tbz
	} {
		if !endsTrapStub(word) {
			t.Fatalf("%#x should end a trap stub", word)
		}
	}

	for _, word := range []uint32{
		0xf9400230, // ldr x16, [x17]
		0xc8e87c09, // casa x8, x9, [x0]
		0xd4001001, // svc #0x80 -- handled at the PC, not as a trail
	} {
		if endsTrapStub(word) {
			t.Fatalf("%#x should not end a trap stub", word)
		}
	}
}
