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
	regX0  = 199
	regX1  = 200
	regX16 = 215
	regX17 = 216
	regX29 = 1
	regX30 = 2
	regSP  = 4
	regPC  = 260
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
		fmt.Fprintf(os.Stderr, "[SAP] fault: PC page %#x origin: %s\n", pc&^0xFFF, r.pageOrigin(pc&^0xFFF))
		fmt.Fprintf(os.Stderr, "[SAP] fault: PC bytes unreadable: %v\n", err)

		return
	}

	word := uint32(code[0]) | uint32(code[1])<<8 | uint32(code[2])<<16 | uint32(code[3])<<24
	fmt.Fprintf(os.Stderr, "[SAP] fault: insn %#08x\n", word)

	target, description, ok := r.accessTarget(word)
	if !ok {
		fmt.Fprintf(os.Stderr, "[SAP] fault: instruction form not decoded, no address\n")

		return
	}

	fmt.Fprintf(os.Stderr, "[SAP] fault: wants %s = %#x (%s)\n", description, target, describeRegion(target))

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

// ExplainFault writes the current fault's detail to stderr.
//
// A guest call that stops inside the SAP machine cannot describe itself: that
// package can read registers but not decode the faulting instruction, and it has
// no idea whether the missing page was ever shipped. This runtime knows both, so
// the machine reaches it through SetFaultExplainer.
func (r *Runtime) ExplainFault() { r.dumpFaultState() }

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
		{"x4", 203}, {"x5", 204}, {"x6", 205}, {"x7", 206}, {"x8", 207},
		// x9-x15 are included because a register-offset load can use any of them
		// as its base, and the fault at 0x1a24c4d04 named x12 that was not
		// printed anywhere.
		{"x9", 208}, {"x10", 209}, {"x11", 210}, {"x12", 211}, {"x13", 212},
		{"x14", 213}, {"x15", 214},
		{"x16", regX16}, {"x17", regX17}, {"x19", 218}, {"x20", 219}, {"x29", regX29},
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

// decodeRegisterAccess reports the operands of a load or store whose offset is
// in a register: `ldr w14, [x12, x16]`.
//
// The immediate decoder above said nothing about the instruction that stopped
// signing at 0x1a24c4d04, so the address, the base register and the reason were
// all missing from the log. Two extend kinds are covered; anything else reports
// ok=false rather than a computed guess.
//
//	base   = bits 9-5
//	index  = bits 20-16
//	option = bits 15-13, the extend kind
//	S      = bit 12, which scales the index by the access size
//
// There is no immediate shift in this form: `[x1, x2, lsl #3]` is option LSL
// with S set on a 64-bit access. Reading bits 15-10 as a shift, which is what
// the first version of this did, produced x16<<26 for `ldr w14, [x12, x16]`.
func decodeRegisterAccess(word uint32) (base, index int, shift uint, unsigned, ok bool) {
	const (
		registerOffsetMask  = 0x3B200C00
		registerOffsetValue = 0x38200800
	)

	if word&registerOffsetMask != registerOffsetValue {
		return 0, 0, 0, false, false
	}

	switch (word >> 13) & 7 {
	case 3: // LSL
	case 2: // UXTW
		unsigned = true
	default: // SXTW, SXTX and anything else
		return 0, 0, 0, false, false
	}

	if word&(1<<12) != 0 {
		shift = uint(word >> 30)
	}

	return int((word >> 5) & 0x1F), int((word >> 16) & 0x1F), shift, unsigned, true
}

// accessTarget works out the address a faulting load or store wanted, in either
// of the two forms this guest uses, and words it the way the log prints it.
func (r *Runtime) accessTarget(word uint32) (uint64, string, bool) {
	if register, offset, ok := decodeAccess(word); ok {
		base, readErr := r.registerValue(register)
		if readErr != nil {
			return 0, "", false
		}

		return base + offset, fmt.Sprintf("[x%d+%#x]", register, offset), true
	}

	baseRegister, indexRegister, shift, unsigned, ok := decodeRegisterAccess(word)
	if !ok {
		return 0, "", false
	}

	base, err := r.registerValue(baseRegister)
	if err != nil {
		return 0, "", false
	}

	index, err := r.registerValue(indexRegister)
	if err != nil {
		return 0, "", false
	}

	if unsigned {
		index = uint64(uint32(index))
	}

	return base + index<<shift, fmt.Sprintf("[x%d+x%d<<%d]", baseRegister, indexRegister, shift), true
}

func (r *Runtime) registerValue(register int) (uint64, error) {
	ordinal, ok := registerOrdinal(register)
	if !ok {
		return 0, fmt.Errorf("arm64 register x%d has no readable ordinal", register)
	}

	return r.engine.RegRead(ordinal)
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
