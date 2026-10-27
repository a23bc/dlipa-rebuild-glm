package emulator

import (
	"encoding/binary"
	"fmt"
	"os"
)

// A guest fault used to be reported as a PC plus an error code, and the address
// that was actually missing had to be inferred. That inference went wrong once
// already: dumpFaultState labelled the PC "faultAddr" and the LR "faultPC", so
// every conclusion drawn from it was about the wrong number.
//
// The address is not inferred any more. The instruction at the PC says which
// register it uses and what offset it adds, so decoding it gives the address
// outright. decodeAccess covers the immediate unsigned-offset load/store family,
// which is what this guest faults in; anything else reports ok=false and the
// caller prints the raw word instead of a guess.

// arm64 register ordinals from include/unicorn/arm64.h at the pinned commit.
const (
	regX0    = 199
	regX1    = 200
	regX16   = 215
	regX17   = 216
	regX29   = 1
	regX30   = 2
	regSP    = 4
	regPC    = 260
)

// far_el1 and esr_el1 are deliberately absent: this build returns 0 for both,
// so printing them only invites conclusions from a constant. See HANDOFF-3 6.3.

// decodeAccess reports the base register and byte offset of an arm64
// load/store with an immediate unsigned offset.
//
//	size = bits 31-30, the access width as a log2 (0=byte .. 3=doubleword)
//	imm12 = bits 21-10, scaled by the access width
//	rn = bits 9-5, the base register
//
// The register number is returned as an arm64 number (0-30), not as a Unicorn
// ordinal; the caller maps it with registerOrdinal.
func decodeAccess(word uint32) (register int, offset uint64, ok bool) {
	const (
		unsignedOffsetMask  = 0x3B000000
		unsignedOffsetValue = 0x39000000
	)

	if word&unsignedOffsetMask != unsignedOffsetValue {
		return 0, 0, false
	}

	size := word >> 30
	imm := uint64((word >> 10) & 0xFFF)

	return int((word >> 5) & 0x1F), imm << size, true
}

// registerOrdinal maps an arm64 register number to the Unicorn ordinal, or
// reports false for a register this diagnostic does not read (xzr, sp).
func registerOrdinal(register int) (int, bool) {
	switch {
	case register >= 0 && register <= 28:
		return regX0 + register, true
	case register == 29:
		return regX29, true
	case register == 30:
		return regX30, true
	default:
		return 0, false
	}
}

// describeRegion names the fixed region an address falls in, if any. open()
// maps these three at constants, so an address outside them came from an image,
// the shared cache, or nowhere.
func describeRegion(address uint64) string {
	switch {
	case address >= heapBase && address < heapBase+heapSize:
		return "heap"
	case address >= stackBase && address < stackBase+stackSize:
		return "stack"
	case address >= returnPC && address < returnPC+4096:
		return "return stub"
	default:
		return "outside heap/stack/stub"
	}
}

// dumpFaultState reports what the guest looked like at the moment a call faulted.
//
// It decodes the instruction at the PC to get the address it wanted, then says
// whether that page is mapped. Reading the address after the fault separates
// "the page left" from "the translation never resolved": uc_mem_read ignores
// guest permissions, so a readable page alongside an unmapped fault means the
// access was refused rather than absent.
func (r *Runtime) dumpFaultState() {
	pc, err := r.engine.RegRead(regPC)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[SAP] fault: PC unreadable: %v\n", err)
		return
	}

	lr, _ := r.engine.RegRead(regX30)
	sp, _ := r.engine.RegRead(regSP)

	fmt.Fprintf(os.Stderr, "[SAP] fault: pc=%#x lr=%#x sp=%#x\n", pc, lr, sp)

	r.dumpRegisters()
	r.dumpCalleeSavedObject()

	code, err := r.engine.MemRead(pc, 4)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[SAP] fault: PC bytes unreadable: %v\n", err)
		return
	}

	word := uint32(code[0]) | uint32(code[1])<<8 | uint32(code[2])<<16 | uint32(code[3])<<24
	fmt.Fprintf(os.Stderr, "[SAP] fault: insn %#08x\n", word)

	register, offset, ok := decodeAccess(word)
	if !ok {
		fmt.Fprintf(os.Stderr, "[SAP] fault: not an immediate load/store, no address decoded\n")

		return
	}

	ordinal, ok := registerOrdinal(register)
	if !ok {
		fmt.Fprintf(os.Stderr, "[SAP] fault: base x%d has no readable ordinal\n", register)

		return
	}

	base, err := r.engine.RegRead(ordinal)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[SAP] fault: x%d unreadable: %v\n", register, err)

		return
	}

	target := base + offset

	fmt.Fprintf(os.Stderr, "[SAP] fault: wants [x%d+%#x] = %#x (%s)\n",
		register, offset, target, describeRegion(target))

	page := target &^ 0xFFF
	fmt.Fprintf(os.Stderr, "[SAP] fault: page %#x origin: %s\n", page, r.pageOrigin(page))

	if _, err = r.engine.MemRead(page, 1); err != nil {
		fmt.Fprintf(os.Stderr, "[SAP] fault: page %#x unmapped: %v\n", page, err)

		return
	}

	if data, err := r.engine.MemRead(target, 16); err != nil {
		fmt.Fprintf(os.Stderr, "[SAP] fault: page %#x mapped but %#x unreadable: %v\n", page, target, err)
	} else {
		fmt.Fprintf(os.Stderr, "[SAP] fault: page %#x mapped, bytes at %#x: %x\n", page, target, data)
	}
}

// pageOrigin says where a page came from: the profile snapshot, the
// shared-cache blob, or neither. "Neither" is the informative answer -- it means
// the real process allocated that memory at runtime and no shipped asset holds
// it, so no amount of remapping will help.
//
// The profile set is tracked separately from Runtime.pages because MemMap
// records every range it maps, cache pages included.
func (r *Runtime) pageOrigin(page uint64) string {
	inProfile := r.profilePages[page]
	inCache := r.cachePages[page]

	switch {
	case inProfile && inCache:
		return "profile page, written over a shared-cache page"
	case inProfile:
		return "profile page"
	case inCache:
		return "shared-cache page"
	default:
		return "neither profile nor cache"
	}
}

// dumpRegisters prints the argument registers plus the two the faulting
// instruction family uses as scratch. Enough to tell a bad self from a bad
// pointer without a wall of output.
func (r *Runtime) dumpRegisters() {
	registers := []struct {
		name    string
		ordinal int
	}{
		{"x0", regX0}, {"x1", regX1}, {"x2", 201}, {"x3", 202},
		{"x4", 203}, {"x5", 204}, {"x6", 205}, {"x7", 206},
		{"x8", 207}, {"x16", regX16}, {"x17", regX17}, {"x19", 218}, {"x20", 219}, {"x29", regX29},
	}

	for _, register := range registers {
		value, err := r.engine.RegRead(register.ordinal)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[SAP] fault: %s unreadable: %v\n", register.name, err)

			continue
		}

		fmt.Fprintf(os.Stderr, "[SAP] fault: %s = %#x\n", register.name, value)
	}
}

// guestBacktrace walks the frame-pointer chain the guest's prologues build
// (stp x29, x30, [sp, #-16]!; mov x29, sp).
//
// Without it a bridge panic names the selector and the receiver and nothing
// else, which is how "unknown receiver ... for copy" left no way to tell which
// call site produced the receiver. The addresses are guest addresses, so
// cmd/pcdecode can turn them into symbols.
func (r *Runtime) guestBacktrace() []string {
	fp, err := r.engine.RegRead(regX29)
	if err != nil || fp == 0 {
		return nil
	}

	out := make([]string, 0, 16)

	for depth := 0; depth < 16; depth++ {
		if fp < stackBase || fp >= stackBase+stackSize || fp%8 != 0 {
			break
		}

		frame, err := r.engine.MemRead(fp, 16)
		if err != nil {
			break
		}

		next := binary.LittleEndian.Uint64(frame)
		lr := binary.LittleEndian.Uint64(frame[8:])

		out = append(out, fmt.Sprintf("#%d %#x", depth, lr))

		if next <= fp {
			break
		}

		fp = next
	}

	return out
}

// dumpCalleeSavedObject prints the object the caller was working on.
//
// The bridge panics with an unknown receiver, and the receiver came out of a
// callee-saved register in the caller's frame -- copyWithZone: loads it with
// ldr x0, [x19, #16]. Reading x19's first words shows which slot holds the bad
// pointer and what sits next to it, which is the difference between "an ivar
// was never set" and "an ivar was overwritten".
func (r *Runtime) dumpCalleeSavedObject() {
	for _, register := range []struct {
		name    string
		ordinal int
	}{{"x19", 218}, {"x20", 219}} {
		object, err := r.engine.RegRead(register.ordinal)
		if err != nil || object == 0 {
			continue
		}

		page := object &^ 0xFFF
		if _, err = r.engine.MemRead(page, 1); err != nil {
			continue
		}

		data, err := r.engine.MemRead(object, 64)
		if err != nil {
			continue
		}

		for offset := 0; offset < len(data); offset += 8 {
			word := binary.LittleEndian.Uint64(data[offset:])
			fmt.Fprintf(os.Stderr, "[SAP] fault: %s[%#x] = %#x\n", register.name, offset, word)
		}
	}
}
