//nolint:wsl // Instruction decoding is clearer when related operations stay together.
package machine

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/a23bc/dlipa-rebuild/sapbridge/internal/sap/unicorn"
)

const (
	arm64AtomicMask = uint32(0xffe0fc00)

	// CAS and SWP each come in four orderings, and the bits that select the
	// ordering sit inside what would otherwise be the opcode. Clearing exactly
	// those bits folds the four into one comparison. The ordering itself changes
	// nothing for this guest: it runs one thread, so there is no other access to
	// acquire or release against.
	//
	//	CAS  sz 0010001 1 Rs o0 11111 Rn Rt   -- o0 is bit 15, the acquire bit 22
	//	SWP  sz 111000 1 Rs ...              -- acquire is bit 23, release bit 22
	//
	// Signing stopped on casa x8, x9, [x0] -- the plain 64-bit form -- because
	// only the *al variants were recognised, and Unicorn raises UC_ERR_EXCEPTION
	// for the rest rather than executing them.
	arm64CASOrdering = uint32(1<<22 | 1<<15)
	arm64SWPOrdering = uint32(1<<23 | 1<<22)

	arm64CAS32  = uint32(0x88a07c00)
	arm64CAS64  = uint32(0xc8a07c00)
	arm64SWP32  = uint32(0xb8208000)
	arm64SWP64  = uint32(0xf8208000)
	arm64CASP32 = uint32(0x08207c00)
	arm64CASP64 = uint32(0x48207c00)

	arm64EOR3Mask = uint32(0xffe08000)
	arm64EOR3     = uint32(0xce000000)

	// svc #imm16. Unicorn does not implement the trap, so a guest that executes
	// one stops with UC_ERR_EXCEPTION -- which is how the comm page's own
	// fallback path ends up here instead of reaching any shim.
	arm64SVCMask = uint32(0xffe0001f)
	arm64SVC     = uint32(0xd4000001)
	arm64RET     = uint32(0xd65f03c0)

	// Mach traps reach the kernel in x16 as negative numbers. -3 is
	// MACH_ABSOLUTE_TIME_TRAP, the one the comm page fallback uses. Non-negative
	// numbers are BSD syscalls, and the stub that issues one branches on the
	// carry flag to find out whether it worked.
	machAbsoluteTimeTrap = uint32(0xfffffffd)
	syscallGettimeofday  = uint32(116)
)

type arm64Compatibility struct {
	engine *unicorn.Engine
	start  time.Time
}

func newARM64Compatibility(engine *unicorn.Engine) *arm64Compatibility {
	return &arm64Compatibility{engine: engine, start: time.Now()}
}

func (c *arm64Compatibility) emulateInvalidInstruction() (bool, error) {
	pc, err := c.engine.RegRead(unicorn.RegPC)
	if err != nil {
		return false, fmt.Errorf("read arm64 instruction address: %w", err)
	}

	data, err := c.engine.MemRead(pc, 4)
	if err != nil {
		return false, nil
	}

	instruction := binary.LittleEndian.Uint32(data)
	if instruction&arm64EOR3Mask == arm64EOR3 {
		if err := c.emulateEOR3(instruction); err != nil {
			return false, err
		}
		if err := c.engine.RegWrite(unicorn.RegPC, pc+4); err != nil {
			return false, fmt.Errorf("advance arm64 instruction address: %w", err)
		}

		return true, nil
	}

	// svc is the one stop where the PC has already moved: an architectural
	// exception leaves the return address on the instruction after the trap. When
	// the trap is at the PC this layer can step over it; when it is not, the word
	// at the PC is what the stub does next, and that shape is checked at the end.
	if isSVC(instruction) {
		if err := c.emulateSVC(); err != nil {
			return false, err
		}

		if err := c.engine.RegWrite(unicorn.RegPC, pc+4); err != nil {
			return false, fmt.Errorf("advance arm64 instruction address: %w", err)
		}

		return true, nil
	}

	if pairWidth, isPair := classifyPairCAS(instruction); isPair {
		if err := c.emulatePairCAS(instruction, pairWidth); err != nil {
			return false, err
		}

		// The shared advance at the end of this function is skipped by this early
		// return, and without it the guest re-executes the same `casp` forever:
		// the first build with CASP support hung here with no message at all,
		// because a retry that never advances looks exactly like slow work.
		if err := c.engine.RegWrite(unicorn.RegPC, pc+4); err != nil {
			return false, fmt.Errorf("advance arm64 instruction address: %w", err)
		}

		return true, nil
	}

	width, isCAS, ok := classifyAtomic(instruction)
	if !ok {
		return c.emulateTrailledSVC(pc, instruction)
	}

	source := (instruction >> 16) & 31
	base := (instruction >> 5) & 31
	destination := instruction & 31

	address, err := c.readBaseRegister(base)
	if err != nil {
		return false, err
	}

	memory, err := c.engine.MemRead(address, width)
	if err != nil {
		return false, fmt.Errorf("read arm64 atomic operand at %#x: %w", address, err)
	}

	oldValue := binary.LittleEndian.Uint64(append(memory, make([]byte, 8-width)...))
	sourceValue, err := c.readValueRegister(source)
	if err != nil {
		return false, err
	}

	if width == 4 {
		sourceValue = uint64(uint32(sourceValue))
	}

	if isCAS {
		newValue, readErr := c.readValueRegister(destination)
		if readErr != nil {
			return false, readErr
		}
		if width == 4 {
			newValue = uint64(uint32(newValue))
		}
		if oldValue == sourceValue {
			if err := c.writeMemoryValue(address, newValue, width); err != nil {
				return false, err
			}
		}
		if err := c.writeValueRegister(source, oldValue); err != nil {
			return false, err
		}
	} else {
		if err := c.writeMemoryValue(address, sourceValue, width); err != nil {
			return false, err
		}
		if err := c.writeValueRegister(destination, oldValue); err != nil {
			return false, err
		}
	}

	if err := c.engine.RegWrite(unicorn.RegPC, pc+4); err != nil {
		return false, fmt.Errorf("advance arm64 instruction address: %w", err)
	}

	return true, nil
}

func (c *arm64Compatibility) emulateEOR3(instruction uint32) error {
	destination := instruction & 31
	first := (instruction >> 5) & 31
	third := (instruction >> 10) & 31
	second := (instruction >> 16) & 31

	firstValue, err := c.engine.RegRead128(unicorn.RegV0 + int(first))
	if err != nil {
		return fmt.Errorf("read arm64 vector register %d: %w", first, err)
	}
	secondValue, err := c.engine.RegRead128(unicorn.RegV0 + int(second))
	if err != nil {
		return fmt.Errorf("read arm64 vector register %d: %w", second, err)
	}
	thirdValue, err := c.engine.RegRead128(unicorn.RegV0 + int(third))
	if err != nil {
		return fmt.Errorf("read arm64 vector register %d: %w", third, err)
	}

	var result [16]byte
	for index := range result {
		result[index] = firstValue[index] ^ secondValue[index] ^ thirdValue[index]
	}
	if err := c.engine.RegWrite128(unicorn.RegV0+int(destination), result); err != nil {
		return fmt.Errorf("write arm64 vector register %d: %w", destination, err)
	}

	return nil
}

// emulatePairCAS performs the compare-and-swap CASP asks for.
//
// Same contract as the single-register form: the source pair holds the expected
// value, the destination pair holds the new one, and the source pair always ends
// up with what the memory held, whether the swap happened or not.
func (c *arm64Compatibility) emulatePairCAS(instruction uint32, width uint64) error {
	source := (instruction >> 16) & 31
	base := (instruction >> 5) & 31
	destination := instruction & 31

	address, err := c.readBaseRegister(base)
	if err != nil {
		return err
	}

	memory, err := c.engine.MemRead(address, width)
	if err != nil {
		return fmt.Errorf("read arm64 pair atomic operand at %#x: %w", address, err)
	}

	half := width / 2

	sourceLow, err := c.readValueRegister(source)
	if err != nil {
		return err
	}

	sourceHigh, err := c.readValueRegister(source + 1)
	if err != nil {
		return err
	}

	actualLow := binary.LittleEndian.Uint64(append(memory[:half], make([]byte, 8-half)...))
	actualHigh := binary.LittleEndian.Uint64(append(memory[half:], make([]byte, 8-half)...))

	if width == 8 {
		sourceLow, sourceHigh = uint64(uint32(sourceLow)), uint64(uint32(sourceHigh))
	}

	if sourceLow == actualLow && sourceHigh == actualHigh {
		destinationLow, readErr := c.readValueRegister(destination)
		if readErr != nil {
			return readErr
		}

		destinationHigh, readErr := c.readValueRegister(destination + 1)
		if readErr != nil {
			return readErr
		}

		if err := c.writeMemoryValue(address, destinationLow, half); err != nil {
			return err
		}

		if err := c.writeMemoryValue(address+half, destinationHigh, half); err != nil {
			return err
		}
	}

	if err := c.writeValueRegister(source, actualLow); err != nil {
		return err
	}

	return c.writeValueRegister(source+1, actualHigh)
}

func (c *arm64Compatibility) readBaseRegister(index uint32) (uint64, error) {
	register := unicorn.RegSP

	if index != 31 {
		var ok bool
		register, ok = arm64GeneralRegister(index)
		if !ok {
			return 0, fmt.Errorf("invalid arm64 base register %d", index)
		}
	}

	value, err := c.engine.RegRead(register)
	if err != nil {
		return 0, fmt.Errorf("read arm64 base register %d: %w", index, err)
	}

	return value, nil
}

func (c *arm64Compatibility) readValueRegister(index uint32) (uint64, error) {
	if index == 31 {
		return 0, nil
	}

	register, ok := arm64GeneralRegister(index)
	if !ok {
		return 0, fmt.Errorf("invalid arm64 value register %d", index)
	}

	value, err := c.engine.RegRead(register)
	if err != nil {
		return 0, fmt.Errorf("read arm64 value register %d: %w", index, err)
	}

	return value, nil
}

func (c *arm64Compatibility) writeValueRegister(index uint32, value uint64) error {
	if index == 31 {
		return nil
	}

	register, ok := arm64GeneralRegister(index)
	if !ok {
		return fmt.Errorf("invalid arm64 value register %d", index)
	}
	if err := c.engine.RegWrite(register, value); err != nil {
		return fmt.Errorf("write arm64 value register %d: %w", index, err)
	}

	return nil
}

func (c *arm64Compatibility) writeMemoryValue(address, value, width uint64) error {
	var data [8]byte

	binary.LittleEndian.PutUint64(data[:], value)
	if err := c.engine.MemWrite(address, data[:width]); err != nil {
		return fmt.Errorf("write arm64 atomic operand at %#x: %w", address, err)
	}

	return nil
}

func (c *arm64Compatibility) instructionAt(address uint64) (uint32, error) {
	data, err := c.engine.MemRead(address, 4)
	if err != nil {
		return 0, err
	}

	return binary.LittleEndian.Uint32(data), nil
}

// isSVC reports whether a word is an svc, whatever immediate it carries. The
// immediate is the trap's own business, not the decoder's.
func isSVC(word uint32) bool { return word&arm64SVCMask == arm64SVC }

// emulateSVC serves a trap the guest reached through an inline svc.
//
// Only what has been seen is here. An unknown number is an error rather than a
// silent zero: the value in x16 names exactly what still needs a shim, and a
// wrong return value would surface much further away than this.
func (c *arm64Compatibility) emulateSVC() error {
	number, err := c.engine.RegRead(unicorn.RegX16)
	if err != nil {
		return fmt.Errorf("read arm64 trap number: %w", err)
	}

	if int32(uint32(number)) < 0 {
		return c.emulateMachTrap(number)
	}

	return c.emulateSyscall(number)
}

// emulateTrailledSVC handles a trap whose exception left the PC on what follows
// it. libsystem's syscall stubs look like this:
//
//	mov x16, #0x74
//	svc #0x80
//	b.lo ok          <- carry clear means the call worked
//	...error path...
//
// and the Mach trap stub ends in `ret` instead. Those shapes are what is checked
// here, because this layer cannot tell one Unicorn error from another and every
// other fault it sees really is at the PC it reports.
func (c *arm64Compatibility) emulateTrailledSVC(pc uint64, instruction uint32) (bool, error) {
	if !endsTrapStub(instruction) {
		return false, nil
	}

	previous, err := c.instructionAt(pc - 4)
	if err != nil || !isSVC(previous) {
		return false, nil
	}

	if err := c.emulateSVC(); err != nil {
		return false, err
	}

	return true, nil
}

// endsTrapStub reports whether a word is what an inline trap stub does next.
func endsTrapStub(word uint32) bool {
	switch {
	case word == arm64RET:
		return true
	case word&0xff000010 == 0x54000000: // b.cond
		return true
	case word&0xfc000000 == 0x14000000: // b
		return true
	case word&0x7e000000 == 0x34000000: // cbz, cbnz
		return true
	case word&0x7e000000 == 0x36000000: // tbz, tbnz
		return true
	default:
		return false
	}
}

func (c *arm64Compatibility) emulateMachTrap(number uint64) error {
	switch uint32(number) {
	case machAbsoluteTimeTrap:
		// mach_absolute_time counts timebase ticks and callers only difference
		// it, so any monotonic source works for the difference. The absolute
		// value still matters to code that turns ticks into a calendar time, and
		// this guest does: the comm page is mapped zero, so libsystem takes its
		// "no timebase" fallback and asks here, then reads seconds from a base of
		// zero. Counting from the machine's start made that base 1970, and the
		// signer returned -42085 with no other explanation. Counting from the
		// Unix epoch keeps the difference and makes the absolute value sane.
		ticks := uint64(time.Now().UnixNano())

		if err := c.engine.RegWrite(unicorn.RegX0, ticks); err != nil {
			return fmt.Errorf("write arm64 trap result: %w", err)
		}

		return nil
	default:
		return fmt.Errorf("guest called mach trap %d (x16 = %#x) with no shim for it",
			int32(uint32(number)), number)
	}
}

func (c *arm64Compatibility) emulateSyscall(number uint64) error {
	switch uint32(number) {
	case syscallGettimeofday:
		timeAddress, err := c.engine.RegRead(unicorn.RegX0)
		if err != nil {
			return fmt.Errorf("read gettimeofday timeval address: %w", err)
		}

		zoneAddress, err := c.engine.RegRead(unicorn.RegX1)
		if err != nil {
			return fmt.Errorf("read gettimeofday zone address: %w", err)
		}

		if timeAddress != 0 {
			if err := writeTimeval(c.engine, timeAddress); err != nil {
				return err
			}
		}

		if zoneAddress != 0 {
			if err := c.engine.MemWrite(zoneAddress, make([]byte, 8)); err != nil {
				return fmt.Errorf("clear guest time zone: %w", err)
			}
		}

		if err := c.engine.RegWrite(unicorn.RegX0, 0); err != nil {
			return fmt.Errorf("write gettimeofday result: %w", err)
		}

		// The stub branches on carry, so a success has to clear it or the guest
		// takes the error path it never asked for.
		return c.setCarry(false)
	default:
		return fmt.Errorf("guest called BSD syscall %d (x16 = %#x) with no shim for it",
			int32(uint32(number)), number)
	}
}

func (c *arm64Compatibility) setCarry(set bool) error {
	nzcv, err := c.engine.RegRead(unicorn.RegNZCV)
	if err != nil {
		return fmt.Errorf("read arm64 flags: %w", err)
	}

	const carry = uint64(1) << 29

	if set {
		nzcv |= carry
	} else {
		nzcv &^= carry
	}

	if err := c.engine.RegWrite(unicorn.RegNZCV, nzcv); err != nil {
		return fmt.Errorf("write arm64 flags: %w", err)
	}

	return nil
}

// writeTimeval fills a guest timeval from the host clock. Shared with the
// gettimeofday shim so the two paths cannot drift apart.
func writeTimeval(engine *unicorn.Engine, address uint64) error {
	now := time.Now()

	var value [16]byte

	binary.LittleEndian.PutUint64(value[0:8], uint64(now.Unix()))
	binary.LittleEndian.PutUint32(value[8:12], uint32(now.Nanosecond()/1000))

	if err := engine.MemWrite(address, value[:]); err != nil {
		return fmt.Errorf("write guest time value: %w", err)
	}

	return nil
}

// classifyAtomic reports an LSE compare-and-swap or swap: the width in bytes,
// whether it is the CAS shape, and whether it is one of those at all.
//
// Split out from the emulation because the masks are the part that has to be
// right: getting them wrong costs a device round to discover, and a test can
// hold every encoding the ARM manual lists instead.
// classifyPairCAS reports CASP, the 128-bit compare-and-swap: two registers are
// compared against two words of memory and swapped as a unit.
//
//	sz=0  casp  W(s), W(s+1), W(t), W(t+1), [Xn]   8 bytes
//	sz=1  casp  X(s), X(s+1), X(t), X(t+1), [Xn]  16 bytes
//
// It is not in classifyAtomic because the operand is a register pair, and every
// other case there is a single register.
func classifyPairCAS(instruction uint32) (width uint64, ok bool) {
	switch instruction & arm64AtomicMask &^ arm64CASOrdering {
	case arm64CASP32:
		return 8, true
	case arm64CASP64:
		return 16, true
	}

	return 0, false
}

func classifyAtomic(instruction uint32) (width uint64, isCAS, ok bool) {
	opcode := instruction & arm64AtomicMask

	switch opcode &^ arm64CASOrdering {
	case arm64CAS32:
		return 4, true, true
	case arm64CAS64:
		return 8, true, true
	}

	switch opcode &^ arm64SWPOrdering {
	case arm64SWP32:
		return 4, false, true
	case arm64SWP64:
		return 8, false, true
	}

	return 0, false, false
}

func arm64GeneralRegister(index uint32) (int, bool) {
	switch {
	case index <= 28:
		return unicorn.RegX0 + int(index), true
	case index == 29:
		return unicorn.RegX29, true
	case index == 30:
		return unicorn.RegLR, true
	default:
		return 0, false
	}
}
