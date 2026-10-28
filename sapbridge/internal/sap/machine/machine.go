package machine

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"os"
	"runtime"
	"time"

	"github.com/a23bc/dlipa-rebuild/sapbridge/internal/sap/assets"
	"github.com/a23bc/dlipa-rebuild/sapbridge/internal/sap/machimage"
	"github.com/a23bc/dlipa-rebuild/sapbridge/internal/sap/unicorn"
)

// init forces the Unicorn archive into the link. The cgo shim in the unicorn
// package carries undefined references to uc_* symbols; without a live
// reference the linker can drop the archive, and purego.Dlsym then fails on
// device with an error that never appears in CI.
func init() {
	unicorn.ForceLink()
}

const sapGuestTimeout = time.Minute

// sapInstructionChunk bounds a single emulation start. Emulation restarts after
// every instruction the compatibility layer emulates, so this is also the
// granularity at which the wall-clock deadline is checked.
const sapInstructionChunk = 20_000_000

// handledRepeatLimit is how many times the compatibility layer may handle the
// same PC with no progress in between before the run is called stuck.
const handledRepeatLimit = 1000

const (
	returnAddress = uint64(0x0000000100000000)
	coreFPBase    = uint64(0x0000100000000000)
	scratchBase   = uint64(0x0000300000000000)
	// Upstream sizes. They had been cut to a quarter for iOS jetsam, and that
	// cut was never validated against the macOS 27 assets: the 10.9 CoreFP has
	// 1,004 rebase fixups, the 27 one has 81,083. Starting from the tightest
	// values turns every unrelated bug into an out-of-memory report, so they
	// start where upstream starts and only shrink if a real device says so.
	scratchSize = uint64(32 << 20)
	heapBase    = uint64(0x0000400000000000)
	heapSize    = uint64(64 << 20)
	stackBase   = uint64(0x0000500000000000)
	stackSize   = uint64(8 << 20)
	stackEnd    = stackBase + stackSize
	// A guest thread gets its thread pointer from the kernel on a real system,
	// and code that touches thread-local storage reads TPIDRRO_EL0 without
	// checking it first. Nothing in the SAP assets installs one, so it is mapped
	// here: zeroed, and pointed at from the middle so the small negative offsets
	// Darwin uses for pthread fields stay inside the block.
	tlsBase    = uint64(0x0000600000000000)
	tlsSize    = uint64(0x2000)
	tlsPointer = tlsBase + tlsSize/2
	// The comm page. libsystem reads the kernel's time data from a fixed address
	// and dereferences it without first checking that anything is mapped there:
	// signing stopped on an ldr from 0xFFFFFC120, built by two instructions a few
	// bytes earlier, and 0xFFFFFC000 is where arm64 keeps the comm page.
	//
	// Zeroed is the answer that helps, because two fields then choose the path
	// the guest already handles. The timebase mode byte at +0x88 is 0, which
	// routes time reads to the svc trap the shims serve; the timestamp at +0x120
	// is 0, which fails the seqlock's own "has anyone filled this in" test. Filling
	// in seconds and a numerator instead would be inventing a contract; a system
	// with no comm page timebase takes the same fallback.
	commPageBase  = uint64(0x0000FFFFFC000)
	commPageSize  = uint64(0x4000)
	pageSize      = uint64(0x1000)
	maxOutputSize = uint64(16 << 20)
)

var coreExportNames = []string{
	"_WIn9UJ86JKdV4dM",
	"_X46O5IeS",
	"_YlCJ3lg",
	"_dku592fbFAj",
	"_fdjkDSAFjklaf2s",
	"_lxpgvVMLd0S7uRl",
}

type entryPoints struct {
	initialize uint64
	exchange   uint64
	sign       uint64
	teardown   uint64
	dispose    uint64
}

type Machine struct {
	engine         *unicorn.Engine
	arm64          *arm64Compatibility
	services       *shims
	entry          entryPoints
	storeAgent     storeAgentEntries
	scratchCursor  uint64
	faultExplainer func()
	closed         bool
}

// SetFaultExplainer installs a callback that describes a guest fault in more
// detail than the registers this package can read.
//
// The useful question after a fault is which address the guest wanted and where
// that page came from, and only the store runtime knows either: it holds the
// instruction decoder the emulator's fault dump uses, and the two sets that say
// whether a page came from the profile, the shared-cache blob, or nowhere. A
// call that dies inside the guest stops here, so the description has to be a
// callback rather than something this package can work out for itself.
func (m *Machine) SetFaultExplainer(explain func()) { m.faultExplainer = explain }

// storeAgentEntries are commerce's entry points, carried by every machine so
// kbsync and decryption can run without a second emulator.
type storeAgentEntries struct {
	globalInit  uint64
	kbsync      uint64
	sessionInit uint64
	decrypt     uint64
	globalClose uint64
}

type imageSpec struct {
	name      string
	data      []byte
	base      uint64
	prelinked map[uint64]string
	slots     map[uint64]string
	functions map[uint64]string
}

type runtimeOptions struct {
	extraImages []imageSpec
	shims       shimOptions
}

// Open starts the emulated runtime a session uses for everything.
//
// It maps the commerce image alongside the signing images. There is room for
// exactly one emulator on iOS: each costs about 173 MB resident, so a second
// uc_open fails inside QEMU's code_gen_alloc with "Could not allocate dynamic
// translator buffer" and exit(1) -- no exception, no crash report -- at the
// 216 MB the first one already holds. kbsync and decryption both need commerce,
// so it is mapped here rather than in a machine of its own.
//
// The four zero-return aliases are the pthread primitives commerce reaches for.
// Registering them unconditionally is harmless for signing, which never calls
// them, and it is what lets one machine serve both.
func Open(ctx context.Context, bundle assets.Bundle) (*Machine, error) {
	machine, exports, err := openRuntime(ctx, bundle, runtimeOptions{
		extraImages: []imageSpec{{name: "commerce", data: bundle.Commerce, base: storeAgentBase}},
		shims:       shimOptions{zeroReturnAliases: storeAgentZeroReturnAliases},
	})
	if err != nil {
		return nil, err
	}

	machine.entry = entryPoints{
		initialize: exports["_cp2g1b9ro"],
		exchange:   exports["_Mib5yocT"],
		sign:       exports["_Fc3vhtJDvr"],
		teardown:   exports["_IPaI1oem5iL"],
		dispose:    exports["_jEHf8Xzsv8K"],
	}
	return machine, nil
}

func openRuntime(ctx context.Context, bundle assets.Bundle, options runtimeOptions) (*Machine, map[string]uint64, error) {
	if ctx == nil {
		return nil, nil, errors.New("SAP runtime context is nil")
	}

	if err := ctx.Err(); err != nil {
		return nil, nil, fmt.Errorf("open SAP runtime: %w", err)
	}

	imageSpecs := make([]imageSpec, 0, 2+len(options.extraImages))
	imageSpecs = append(imageSpecs,
		imageSpec{name: "CoreFP", data: bundle.CoreFP, base: coreFPBase},
		imageSpec{
			name:      "AppleMediaServices",
			data:      bundle.AppleMediaServices,
			prelinked: macOS27SharedCacheFunctions,
			slots:     macOS27SharedCacheSlots,
			functions: macOS27SharedCacheFunctions,
		},
	)
	imageSpecs = append(imageSpecs, options.extraImages...)

	images := make(map[string]*machimage.Image, len(imageSpecs))

	for _, spec := range imageSpecs {
		image, err := machimage.Open(spec.name, spec.data)
		if err != nil {
			return nil, nil, fmt.Errorf("open %s image: %w", spec.name, err)
		}

		images[spec.name] = image
	}

	exports := make(map[string]uint64)
	coreExports := make(map[string]uint64, len(coreExportNames))
	coreFP := images["CoreFP"]

	for _, name := range coreExportNames {
		address, err := coreFP.Export(name, coreFPBase)
		if err != nil {
			return nil, nil, fmt.Errorf("resolve CoreFP export %s: %w", name, err)
		}

		exports[name] = address
		coreExports[name] = address
	}

	appleMediaServices := images["AppleMediaServices"]
	for _, name := range []string{
		"_cp2g1b9ro",
		"_Mib5yocT",
		"_Fc3vhtJDvr",
		"_IPaI1oem5iL",
		"_jEHf8Xzsv8K",
	} {
		address, err := appleMediaServices.Export(name, appleMediaServices.Base())
		if err != nil {
			return nil, nil, fmt.Errorf("resolve AppleMediaServices export %s: %w", name, err)
		}

		exports[name] = address
	}

	if err := ctx.Err(); err != nil {
		return nil, nil, fmt.Errorf("open SAP runtime: %w", err)
	}

	engine, err := unicorn.New(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("create Unicorn engine: %w", err)
	}

	machine := &Machine{engine: engine, arm64: newARM64Compatibility(engine)}
	// Every machine carries these, because both callers need them: Open serves a
	// whole session, and openStoreAgentGlobal serves decryption. A machine that
	// left them zero would invoke address 0 the first time it ran commerce.
	machine.storeAgent = storeAgentEntries{
		globalInit:  storeAgentGlobalInit,
		kbsync:      storeAgentKBSyncEntry,
		sessionInit: storeAgentSessionInit,
		decrypt:     storeAgentDecryptEntry,
		globalClose: storeAgentGlobalClose,
	}
	ready := false

	defer func() {
		if !ready {
			_ = machine.Close()
		}
	}()

	for _, region := range []struct {
		address uint64
		size    uint64
	}{
		{returnAddress, pageSize},
		{scratchBase, scratchSize},
		{heapBase, heapSize},
		{stackBase, stackSize},
		{tlsBase, tlsSize},
		{commPageBase, commPageSize},
	} {
		// The first of these triggers UC_INIT, and with it QEMU's
		// code_gen_alloc. That function calls exit(1) when its mmap fails, so the
		// process dies inside this loop and the last line printed is the only
		// clue to which region was in flight.
		fmt.Fprintf(os.Stderr, "[SAP]   mem_map %#x size=%d (triggers UC_INIT on the first)\n",
			region.address, region.size)

		if err := engine.MemMap(region.address, region.size); err != nil {
			return nil, nil, fmt.Errorf("map SAP guest memory at %#x: %w", region.address, err)
		}
	}

	if err := engine.MemWrite(returnAddress, []byte{0x00, 0x00, 0x20, 0xd4}); err != nil {
		return nil, nil, fmt.Errorf("write SAP guest return instruction: %w", err)
	}

	// Set before anything runs: the shims reach into the guest during setup, and
	// the first TLS access is what stopped signing at 0x18089c55c.
	engine.SetThreadPointer(tlsPointer)

	fmt.Fprintf(os.Stderr, "[SAP] thread pointer %#x (TLS %#x+%#x)\n", tlsPointer, tlsBase, tlsSize)

	machine.services, err = newShimsWithOptions(engine, coreExports, bundle.CoreFPICXS, options.shims)
	if err != nil {
		return nil, nil, err
	}

	resolver := func(name string) (uint64, error) {
		if address, ok := exports[name]; ok {
			return address, nil
		}

		return machine.services.resolve(name)
	}

	for _, spec := range imageSpecs {
		if err := loadPrelinkedSlots(engine, spec.slots, resolver); err != nil {
			return nil, nil, fmt.Errorf("load %s shared-cache slots: %w", spec.name, err)
		}

		if err := loadPrelinkedFunctions(engine, spec.functions, resolver); err != nil {
			return nil, nil, fmt.Errorf("load %s shared-cache functions: %w", spec.name, err)
		}
	}

	for _, spec := range imageSpecs {
		image := images[spec.name]

		var err error

		if spec.prelinked != nil {
			err = image.PreparePrelinked(spec.prelinked, resolver)
		} else {
			err = image.Relocate(spec.base, resolver)
		}

		if err != nil {
			return nil, nil, fmt.Errorf("relocate SAP guest image: %w", err)
		}

		if err := image.Load(engine); err != nil {
			return nil, nil, fmt.Errorf("load SAP guest image: %w", err)
		}
	}

	// Drop references to the source Mach-O bytes so the GC can reclaim
	// them. imageSpecs holds slices pointing into bundle.CoreFP /
	// bundle.AppleMediaServices / bundle.Commerce (~118 MB combined);
	// image.Load() already dropped i.data inside each Image. Clearing
	// imageSpecs here lets runtime.GC() below actually return that
	// memory to the OS.
	imageSpecs = nil

	// All Mach-O segment bytes have been copied into Unicorn guest memory.
	// image.Load() dropped the Go-side i.data / i.file references, but the
	// GC may not have collected them yet. Force a GC + scavenge here so
	// the ~110 MB of retained asset bytes (CoreFP 95 MB + AppleMediaServices
	// 15 MB) is returned to the OS before the SAP handshake starts
	// allocating scratch/heap inside Unicorn. Without this, Go heap +
	// Unicorn regions together push RSS past iOS's per-process ceiling
	// and the app gets SIGKILL'd during guest.Initialize().
	runtime.GC()
	runtime.GC() // run twice: first pass finalizes, second pass sweeps

	ready = true

	return machine, exports, nil
}

func loadPrelinkedFunctions(engine *unicorn.Engine, functions map[uint64]string, resolve func(string) (uint64, error)) error {
	pages := make(map[uint64]struct{})
	for address := range functions {
		pages[address-address%pageSize] = struct{}{}
		end := address + 15
		pages[end-end%pageSize] = struct{}{}
	}

	for address := range pages {
		if err := engine.MemMap(address, pageSize); err != nil {
			return fmt.Errorf("map function page at %#x: %w", address, err)
		}
	}

	for address, name := range functions {
		target, err := resolve(name)
		if err != nil {
			return fmt.Errorf("resolve %s: %w", name, err)
		}

		trampoline := make([]byte, 16)
		binary.LittleEndian.PutUint32(trampoline[0:4], 0x58000050) // ldr x16, #8
		binary.LittleEndian.PutUint32(trampoline[4:8], 0xd61f0200) // br x16
		binary.LittleEndian.PutUint64(trampoline[8:16], target)

		if err := engine.MemWrite(address, trampoline); err != nil {
			return fmt.Errorf("write %s trampoline at %#x: %w", name, address, err)
		}
	}

	return nil
}

func loadPrelinkedSlots(engine *unicorn.Engine, slots map[uint64]string, resolve func(string) (uint64, error)) error {
	pages := make(map[uint64]struct{})
	for address := range slots {
		pages[address-address%pageSize] = struct{}{}
	}

	for address := range pages {
		if err := engine.MemMap(address, pageSize); err != nil {
			return fmt.Errorf("map slot page at %#x: %w", address, err)
		}
	}

	for address, name := range slots {
		value, err := resolve(name)
		if err != nil {
			return fmt.Errorf("resolve %s: %w", name, err)
		}

		var data [8]byte

		binary.LittleEndian.PutUint64(data[:], value)

		if err := engine.MemWrite(address, data[:]); err != nil {
			return fmt.Errorf("write %s slot at %#x: %w", name, address, err)
		}
	}

	return nil
}

// Engine returns the guest this machine runs on.
//
// Exposed because the Store runtime must run on the same guest rather than
// create one: iOS allows roughly one emulator per process, so a second one
// fails outright.
func (m *Machine) Engine() *unicorn.Engine {
	if m == nil {
		return nil
	}

	return m.engine
}

func (m *Machine) Initialize(hardwareID []byte) (uint64, error) {
	hardware, err := hardwareBlock(hardwareID)
	if err != nil {
		return 0, err
	}

	m.beginCall()

	defer m.clearScratch()

	contextField, err := m.scratch(nil, 8)
	if err != nil {
		return 0, err
	}

	hardwareAddress, err := m.scratch(hardware, uint64(len(hardware)))
	if err != nil {
		return 0, err
	}

	status, err := m.invoke(m.entry.initialize, contextField, hardwareAddress)
	if err != nil {
		return 0, err
	}

	if int32(status) != 0 {
		return 0, fmt.Errorf("SAP initialization returned %d", int32(status))
	}

	contextValue, err := m.readUint64(contextField)
	if err != nil {
		return 0, err
	}

	if contextValue == 0 {
		return 0, errors.New("SAP initialization returned a null context")
	}

	return contextValue, nil
}

func (m *Machine) Exchange(version uint32, hardwareID []byte, contextValue uint64, input []byte) ([]byte, int32, error) {
	if uint64(len(input)) > math.MaxUint32 {
		return nil, 0, errors.New("SAP exchange input is too large")
	}

	hardware, err := hardwareBlock(hardwareID)
	if err != nil {
		return nil, 0, err
	}

	m.beginCall()

	defer m.clearScratch()

	hardwareAddress, err := m.scratch(hardware, uint64(len(hardware)))
	if err != nil {
		return nil, 0, err
	}

	inputAddress, err := m.scratch(input, uint64(len(input)))
	if err != nil {
		return nil, 0, err
	}

	outputField, err := m.scratch(nil, 8)
	if err != nil {
		return nil, 0, err
	}

	lengthField, err := m.scratch(nil, 8)
	if err != nil {
		return nil, 0, err
	}

	resultField, err := m.scratch(nil, 4)
	if err != nil {
		return nil, 0, err
	}

	status, err := m.invoke(
		m.entry.exchange,
		uint64(version),
		hardwareAddress,
		contextValue,
		inputAddress,
		uint64(len(input)),
		outputField,
		lengthField,
		resultField,
	)
	if err != nil {
		return nil, 0, err
	}

	if int32(status) != 0 {
		return nil, 0, fmt.Errorf("SAP exchange returned %d", int32(status))
	}

	output, err := m.consumeOutput(outputField, lengthField)
	if err != nil {
		return nil, 0, err
	}

	result, err := m.readUint32(resultField)
	if err != nil {
		return nil, 0, err
	}

	return output, int32(result), nil
}

func (m *Machine) Sign(contextValue uint64, input []byte) ([]byte, error) {
	if uint64(len(input)) > math.MaxUint32 {
		return nil, errors.New("SAP signing input is too large")
	}

	m.beginCall()

	defer m.clearScratch()

	inputAddress, err := m.scratch(input, uint64(len(input)))
	if err != nil {
		return nil, err
	}

	outputField, err := m.scratch(nil, 8)
	if err != nil {
		return nil, err
	}

	lengthField, err := m.scratch(nil, 8)
	if err != nil {
		return nil, err
	}

	status, err := m.invoke(
		m.entry.sign,
		contextValue,
		inputAddress,
		uint64(len(input)),
		outputField,
		lengthField,
	)
	if err != nil {
		return nil, err
	}

	if int32(status) != 0 {
		return nil, fmt.Errorf("SAP signing returned %d", int32(status))
	}

	output, err := m.consumeOutput(outputField, lengthField)
	if err != nil {
		return nil, err
	}

	return output, nil
}

func (m *Machine) Teardown(contextValue uint64) error {
	status, err := m.invoke(m.entry.teardown, contextValue)
	if err != nil {
		return err
	}

	if int32(status) != 0 {
		return fmt.Errorf("SAP teardown returned %d", int32(status))
	}

	return nil
}

func (m *Machine) dispose(output uint64) error {
	status, err := m.invoke(m.entry.dispose, output)
	if err != nil {
		return err
	}

	if int32(status) != 0 {
		return fmt.Errorf("SAP storage disposal returned %d", int32(status))
	}

	return nil
}

//nolint:wsl // Register setup and compatibility retries are clearer in execution order.
func (m *Machine) invoke(function uint64, arguments ...uint64) (uint64, error) {
	if m.closed {
		return 0, errors.New("SAP guest machine is closed")
	}

	if function == 0 {
		return 0, errors.New("SAP guest entry point is unavailable")
	}

	registers := [...]int{
		unicorn.RegX0,
		unicorn.RegX1,
		unicorn.RegX2,
		unicorn.RegX3,
		unicorn.RegX4,
		unicorn.RegX5,
		unicorn.RegX6,
		unicorn.RegX7,
	}
	for index, register := range registers {
		var value uint64
		if index < len(arguments) {
			value = arguments[index]
		}

		if err := m.engine.RegWrite(register, value); err != nil {
			return 0, fmt.Errorf("write SAP guest argument register: %w", err)
		}
	}

	extra := max(len(arguments)-len(registers), 0)

	stackPointer := stackEnd - uint64(extra)*8
	stackPointer -= stackPointer % 16

	for index := range extra {
		if err := m.writeUint64(stackPointer+uint64(index)*8, arguments[len(registers)+index]); err != nil {
			return 0, err
		}
	}

	if err := m.engine.RegWrite(unicorn.RegSP, stackPointer); err != nil {
		return 0, fmt.Errorf("write SAP guest stack register: %w", err)
	}
	if err := m.engine.RegWrite(unicorn.RegLR, returnAddress); err != nil {
		return 0, fmt.Errorf("write SAP guest return register: %w", err)
	}

	m.services.resetFault()

	// SAP's cryptographic routines have input- and host-dependent instruction
	// counts. Bound execution by wall time without rejecting legitimate work on
	// slower machines for crossing a fixed instruction limit.
	//
	// The wall time is enforced here rather than through Unicorn's timeout: that
	// timeout is a QEMU timer with a thread behind it, this loop restarts
	// emulation once per instruction the compatibility layer emulates, and the
	// signer hits enough of those to exhaust the process's threads --
	// "qemu_thread_create: Resource temporarily unavailable" at 0x18088a368,
	// which is a `casp` in a crypto loop. Chunks of instructions bound the same
	// wait without a thread.
	deadline := time.Now().Add(sapGuestTimeout)
	repeats := 0
	next := function

	for {
		executionErr := m.engine.StartBounded(next, returnAddress, 0, sapInstructionChunk)
		if executionErr == nil {
			pc, readErr := m.engine.RegRead(unicorn.RegPC)
			if readErr != nil {
				return 0, fmt.Errorf("read SAP guest instruction register: %w", readErr)
			}

			if pc == returnAddress {
				break
			}

			// The chunk ran out rather than the function returning.
			if time.Now().After(deadline) {
				return 0, fmt.Errorf("SAP guest exceeded %s at %#x", sapGuestTimeout, pc)
			}

			next = pc

			continue
		}
		if m.services.fault != nil {
			return 0, m.services.fault
		}

		if m.arm64 != nil {
			before, pcErr := m.engine.RegRead(unicorn.RegPC)
			if pcErr != nil {
				return 0, fmt.Errorf("read SAP guest instruction register: %w", pcErr)
			}

			handled, compatibilityErr := m.arm64.emulateInvalidInstruction()
			if compatibilityErr != nil {
				return 0, compatibilityErr
			}
			if handled {
				next, compatibilityErr = m.engine.RegRead(unicorn.RegPC)
				if compatibilityErr != nil {
					return 0, fmt.Errorf("resume SAP guest function: %w", compatibilityErr)
				}

				// A handler that forgets to advance re-runs the same instruction
				// for as long as the caller is willing to wait: the first CASP
				// support hung for five minutes and printed nothing.
				//
				// "PC did not change" is not the test, though -- the trailing svc
				// case at 0x180849118 leaves the PC where the exception already
				// put it, and that is correct. What is never correct is handling
				// the same PC over and over with nothing in between, so that is
				// what is counted.
				if next == before {
					repeats++

					if repeats > handledRepeatLimit {
						return 0, fmt.Errorf("arm64 compatibility handled %#x %d times without progress", before, repeats)
					}
				} else {
					repeats = 0
				}

				continue
			}
		}

		instruction, readErr := m.engine.RegRead(unicorn.RegPC)
		if readErr != nil {
			return 0, fmt.Errorf("execute SAP guest function: %w", executionErr)
		}
		// The entry and the link register say where the call came from; the
		// instruction at the faulting PC is what actually failed. Unicorn reports
		// UC_ERR_EXCEPTION for anything the CPU cannot execute, and guessing
		// which one it was has already cost a build.
		stopped, _ := m.engine.RegRead(unicorn.RegPC)

		if m.faultExplainer != nil {
			m.faultExplainer()
		}

		return 0, fmt.Errorf("execute SAP guest function at %#x from %#x: %w; %s",
			instruction, m.linkRegister(), executionErr, m.describeStop(stopped))
	}

	if m.services.fault != nil {
		return 0, m.services.fault
	}

	instruction, err := m.engine.RegRead(unicorn.RegPC)
	if err != nil {
		return 0, fmt.Errorf("read SAP guest instruction register: %w", err)
	}

	if instruction != returnAddress {
		return 0, fmt.Errorf("SAP guest stopped unexpectedly: %s", m.describeStop(instruction))
	}

	result, err := m.engine.RegRead(unicorn.RegX0)
	if err != nil {
		return 0, fmt.Errorf("read SAP guest result register: %w", err)
	}

	return result, nil
}

func (m *Machine) beginCall() {
	m.scratchCursor = 0
}

func (m *Machine) scratch(data []byte, size uint64) (uint64, error) {
	reserved := align(max(size, 1), 16)
	if m.scratchCursor > scratchSize || reserved > scratchSize-m.scratchCursor {
		return 0, errors.New("SAP guest scratch space exhausted")
	}

	address := scratchBase + m.scratchCursor
	m.scratchCursor += reserved

	if len(data) != 0 {
		if uint64(len(data)) > size {
			return 0, errors.New("scratch data exceeds reservation")
		}

		if err := m.engine.MemWrite(address, data); err != nil {
			return 0, fmt.Errorf("write SAP guest scratch data: %w", err)
		}
	} else if size != 0 {
		if err := m.engine.MemWrite(address, make([]byte, size)); err != nil {
			return 0, fmt.Errorf("clear SAP guest scratch data: %w", err)
		}
	}

	return address, nil
}

func (m *Machine) clearScratch() {
	if m.scratchCursor != 0 && m.engine != nil && !m.closed {
		_ = m.engine.MemWrite(scratchBase, make([]byte, m.scratchCursor))
	}

	m.scratchCursor = 0
}

func (m *Machine) consumeOutput(pointerField, lengthField uint64) ([]byte, error) {
	pointer, err := m.readUint64(pointerField)
	if err != nil {
		return nil, err
	}

	length, err := m.readUint64(lengthField)
	if err != nil {
		return nil, err
	}

	var output []byte

	var outputErr error

	switch {
	case length > maxOutputSize:
		outputErr = fmt.Errorf("SAP output is %d bytes, maximum is %d", length, maxOutputSize)
	case length == 0:
	case pointer == 0:
		outputErr = errors.New("SAP returned a null output pointer")
	default:
		output, outputErr = m.engine.MemRead(pointer, length)
	}

	var disposeErr error
	if pointer != 0 {
		disposeErr = m.dispose(pointer)
	}

	return output, errors.Join(outputErr, disposeErr)
}

func (m *Machine) readUint32(address uint64) (uint32, error) {
	data, err := m.engine.MemRead(address, 4)
	if err != nil {
		return 0, fmt.Errorf("read SAP guest uint32: %w", err)
	}

	return binary.LittleEndian.Uint32(data), nil
}

func (m *Machine) readUint64(address uint64) (uint64, error) {
	data, err := m.engine.MemRead(address, 8)
	if err != nil {
		return 0, fmt.Errorf("read SAP guest uint64: %w", err)
	}

	return binary.LittleEndian.Uint64(data), nil
}

func (m *Machine) writeUint64(address, value uint64) error {
	var data [8]byte

	binary.LittleEndian.PutUint64(data[:], value)

	if err := m.engine.MemWrite(address, data[:]); err != nil {
		return fmt.Errorf("write SAP guest uint64: %w", err)
	}

	return nil
}

func (m *Machine) Close() error {
	if m == nil || m.closed {
		return nil
	}

	m.closed = true

	var errs []error

	if m.services != nil {
		errs = append(errs, m.services.close())
	}

	if m.engine != nil {
		errs = append(errs, m.engine.Close())
	}

	return errors.Join(errs...)
}

func hardwareBlock(hardwareID []byte) ([]byte, error) {
	if len(hardwareID) == 0 || len(hardwareID) > 20 {
		return nil, errors.New("hardware ID must contain between 1 and 20 bytes")
	}

	result := make([]byte, 24)
	binary.LittleEndian.PutUint32(result[0:4], uint32(len(hardwareID)))
	copy(result[4:], hardwareID)

	return result, nil
}

func align(value, alignment uint64) uint64 {
	return (value + alignment - 1) &^ (alignment - 1)
}

// HeapUsed reports how far this machine's guest allocator has advanced.
//
// The store runtime shares the same 64 MB heap region -- one engine, one
// address space -- so it has to start above this or it will hand out memory the
// handshake is still using. Clearing an allocation then destroys live session
// state, and the next Sign fails somewhere unrelated.
func (m *Machine) HeapUsed() uint64 {
	if m == nil || m.services == nil {
		return 0
	}

	return m.services.heapCursor
}

// describeStop says where the guest ended up and how it got there.
//
// "stopped unexpectedly at 0x..." names one address and nothing else, which is
// not enough to tell a jump into unmapped memory from a return to the wrong
// frame. The link register and the frame chain say which call produced it.
func (m *Machine) describeStop(pc uint64) string {
	link, _ := m.engine.RegRead(unicorn.RegLR)
	x0, _ := m.engine.RegRead(unicorn.RegX0)
	x1, _ := m.engine.RegRead(unicorn.RegX1)

	frames := make([]string, 0, 8)

	if fp, err := m.engine.RegRead(unicorn.RegX29); err == nil && fp != 0 {
		for depth := 0; depth < 8; depth++ {
			frame, err := m.engine.MemRead(fp, 16)
			if err != nil {
				break
			}

			next := binary.LittleEndian.Uint64(frame)
			returned := binary.LittleEndian.Uint64(frame[8:])

			frames = append(frames, fmt.Sprintf("#%d %#x", depth, returned))

			if next <= fp {
				break
			}

			fp = next
		}
	}

	instruction := ""

	if word, err := m.engine.MemRead(pc, 4); err == nil {
		instruction = fmt.Sprintf("insn=%#x", binary.LittleEndian.Uint32(word))
	} else {
		instruction = "insn=<unreadable>"
	}

	return fmt.Sprintf("pc=%#x %s lr=%#x x0=%#x x1=%#x x8=%#x back=%v",
		pc, instruction, link, x0, x1, m.register(unicorn.RegX0+8), frames)
}

// linkRegister reads LR without failing the caller when the engine is gone.
func (m *Machine) linkRegister() uint64 {
	value, _ := m.engine.RegRead(unicorn.RegLR)

	return value
}

func (m *Machine) register(ordinal int) uint64 {
	value, _ := m.engine.RegRead(ordinal)

	return value
}
