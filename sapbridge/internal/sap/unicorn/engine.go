package unicorn

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/ebitengine/purego"
)

const (
	queryTimeout     = 4
	controlCPUModel  = uint32(7 | 1<<26 | 1<<30)
	arm64CPUModelMax = uint32(3)

	// UC_CTL_WRITE(UC_CTL_TCG_BUFFER_SIZE, 1) = 13 | (1<<26) | (1<<30).
	// Shrinks Unicorn's JIT translation cache from the 1 GiB default
	// (DEFAULT_CODE_GEN_BUFFER_SIZE_1 for 64-bit TCG) to a value that
	// fits inside an iOS app's per-process memory ceiling. Without this
	// call, uc_open → uc_init_engine → tcg_exec_init → code_gen_alloc
	// mmaps 1 GiB of anonymous memory and iOS refuses, producing the
	// stderr message "Could not allocate dynamic translator buffer"
	// followed by exit(1).
	//
	// The control must be invoked after uc_open but BEFORE any other
	// Unicorn call that would trigger UC_INIT (uc_mem_map, uc_emu_start,
	// uc_reg_write, etc). The WRITE path of UC_CTL_TCG_BUFFER_SIZE does
	// NOT trigger UC_INIT — it just stores the size — so calling it
	// first means the later UC_INIT will use the smaller size when it
	// finally runs tcg_exec_init(uc, uc->tcg_buffer_size).
	//
	// 8 MiB is a middle ground. 16 MiB worked on one launch but failed
	// on another with "Could not allocate dynamic translator buffer" —
	// iOS's per-process virtual address ceiling is tight when Go heap
	// is already 126 MB. 8 MiB leaves more headroom while still giving
	// the JIT enough room for SAP handshake code. The Unicorn patch
	// prints errno on mmap failure so we can see the real reason if
	// this still fails.
	controlTCGBufferSize = uint32(13 | 1<<26 | 1<<30)
	tcgBufferSizeIOS     = uint32(8 << 20) // 8 MiB
)

const (
	archARM64 = 2
	modeARM   = 0
	protAll   = 7

	RegX29  = 1
	RegLR   = 2
	RegNZCV = 3
	RegSP   = 4
	RegX0   = 199
	RegX1   = 200
	RegX2   = 201
	RegX3   = 202
	RegX4   = 203
	RegX5   = 204
	RegX6   = 205
	RegX7   = 206
	RegX8   = 207
	RegX14  = 213
	RegX15  = 214
	RegX16  = 215
	RegV0   = 228
	RegPC   = 260

	// Thread pointer registers. Guest code that touches thread-local storage
	// reads TPIDRRO_EL0 and expects a pointer the kernel would have installed;
	// with the register clear, the first such access faults on address 0x18 --
	// which is what stopped the Store signer at 0x18089c55c, an mrs/ldr pair
	// whose ldr had no memory to read.
	RegTPIDR_EL0   = 263
	RegTPIDRRO_EL0 = 264
)

var (
	errTimeout      = errors.New("unicorn emulation timed out")
	errEngineClosed = errors.New("unicorn engine is closed")
)

type api struct {
	version    func(*uint32, *uint32) uint32
	open       func(int32, int32, *uintptr) int32
	close      func(uintptr) int32
	query      func(uintptr, int32, *uint64) int32
	ctl        func(uintptr, uint32, uint32) int32
	strerror   func(int32) string
	memMap     func(uintptr, uint64, uint64, uint32) int32
	memProtect func(uintptr, uint64, uint64, uint32) int32
	memUnmap   func(uintptr, uint64, uint64) int32
	memRead    func(uintptr, uint64, unsafe.Pointer, uint64) int32
	memWrite   func(uintptr, uint64, unsafe.Pointer, uint64) int32
	regRead    func(uintptr, int32, unsafe.Pointer) int32
	regWrite   func(uintptr, int32, unsafe.Pointer) int32
	emuStart   func(uintptr, uint64, uint64, uint64, uint64) int32
	emuStop    func(uintptr) int32
	hookAdd    func(uintptr, *uintptr, int32, uintptr, uintptr, uint64, uint64) int32
	hookDel    func(uintptr, uintptr) int32
}

type Engine struct {
	api           api
	handle        uintptr
	library       library
	hooks         hookState
	threadPointer uint64
	stateMu       sync.Mutex
	active        sync.WaitGroup
	closing       bool
	closeDone     chan struct{}
	closeErr      error
	regionsMu     sync.Mutex
	regions       []mappedRegion
}

// mappedRegion is one uc_mem_map call, kept so a later tenant of the same engine
// can tell what is already there.
type mappedRegion struct {
	start uint64
	end   uint64
}

// IsMapped reports whether [address, address+size) is already mapped.
//
// The engine is shared: the SAP machine maps its images and pages long before the
// Store runtime opens, and the runtime has to know that so it does not write
// pristine copies over memory the machine has since changed.
func (e *Engine) IsMapped(address, size uint64) bool {
	end := address + size

	e.regionsMu.Lock()
	defer e.regionsMu.Unlock()

	for _, region := range e.regions {
		if region.start <= address && end <= region.end {
			return true
		}
	}

	return false
}

// SetThreadPointer points the guest's thread pointer registers at a TLS block.
//
// Every guest entry rewrites both registers, because they are part of the
// context a caller may have replaced. Call it once during setup with a mapped,
// zeroed address: the guest only reads and writes the block, it does not expect
// to allocate it.
func (e *Engine) SetThreadPointer(address uint64) { e.threadPointer = address }

func New(ctx context.Context) (*Engine, error) {
	return newEngine(ctx, openLibrary)
}

func newEngine(ctx context.Context, loadLibrary func(context.Context) (library, error)) (*Engine, error) {
	if ctx == nil {
		return nil, errors.New("unicorn context is nil")
	}

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("create Unicorn engine: %w", err)
	}

	library, err := loadLibrary(ctx)
	if err != nil {
		return nil, fmt.Errorf("load Unicorn: %w", err)
	}

	if err := ctx.Err(); err != nil {
		if library.handle != 0 && library.close != nil {
			_ = library.close()
		}

		return nil, fmt.Errorf("create Unicorn engine: %w", err)
	}

	engine := &Engine{
		library:   library,
		closeDone: make(chan struct{}),
	}
	engine.register(library.handle)

	var major, minor uint32

	engine.api.version(&major, &minor)

	if major != 2 || minor != 1 {
		_ = library.close()

		return nil, fmt.Errorf("unsupported Unicorn API version %d.%d", major, minor)
	}

	// Print around each step that can fail silently. The failure this guards
	// against happens inside QEMU, which calls exit(1) from code_gen_alloc, so
	// the process dies mid-function and the only evidence is which of these
	// lines came last.
	fmt.Fprintf(os.Stderr, "[SAP]   uc_open(arch=%d mode=%d)...\n", archARM64, modeARM)

	if err := engine.err(engine.api.open(archARM64, modeARM, &engine.handle)); err != nil {
		_ = library.close()

		return nil, fmt.Errorf("create arm64 emulator: %w", err)
	}

	fmt.Fprintf(os.Stderr, "[SAP]   uc_open ok\n")

	// Shrink the TCG JIT translation buffer from the 1 GiB default to
	// 16 MiB. MUST happen before any UC_INIT-triggering call (uc_mem_map,
	// uc_emu_start, uc_reg_write, uc_ctl READ, etc.) so that the eventual
	// tcg_exec_init picks up the smaller size. The WRITE path of
	// UC_CTL_TCG_BUFFER_SIZE just stores the value; it does not init.
	// Without this, iOS refuses the 1 GiB mmap and Unicorn exits with
	// "Could not allocate dynamic translator buffer".
	fmt.Fprintf(os.Stderr, "[SAP]   uc_ctl tcg_buffer_size=%d\n", tcgBufferSizeIOS)

	if err := engine.err(engine.api.ctl(engine.handle, controlTCGBufferSize, tcgBufferSizeIOS)); err != nil {
		_ = engine.api.close(engine.handle)
		_ = library.close()

		return nil, fmt.Errorf("set TCG buffer size: %w", err)
	}

	// Select Unicorn's most capable ARM64 model. The compatibility layer handles
	// modern instructions that this Unicorn build does not implement.
	if err := engine.err(engine.api.ctl(engine.handle, controlCPUModel, arm64CPUModelMax)); err != nil {
		_ = engine.api.close(engine.handle)
		_ = library.close()

		return nil, fmt.Errorf("configure arm64 CPU model: %w", err)
	}

	if err := configureEngine(engine); err != nil {
		_ = engine.api.close(engine.handle)
		_ = library.close()

		return nil, err
	}

	runtime.SetFinalizer(engine, func(engine *Engine) {
		_ = engine.Close()
	})

	return engine, nil
}

func (e *Engine) register(handle uintptr) {
	purego.RegisterLibFunc(&e.api.version, handle, "uc_version")
	purego.RegisterLibFunc(&e.api.open, handle, "uc_open")
	purego.RegisterLibFunc(&e.api.close, handle, "uc_close")
	purego.RegisterLibFunc(&e.api.query, handle, "uc_query")
	purego.RegisterLibFunc(&e.api.ctl, handle, "uc_ctl")
	purego.RegisterLibFunc(&e.api.strerror, handle, "uc_strerror")
	purego.RegisterLibFunc(&e.api.memMap, handle, "uc_mem_map")
	purego.RegisterLibFunc(&e.api.memProtect, handle, "uc_mem_protect")
	purego.RegisterLibFunc(&e.api.memUnmap, handle, "uc_mem_unmap")
	purego.RegisterLibFunc(&e.api.memRead, handle, "uc_mem_read")
	purego.RegisterLibFunc(&e.api.memWrite, handle, "uc_mem_write")
	purego.RegisterLibFunc(&e.api.regRead, handle, "uc_reg_read")
	purego.RegisterLibFunc(&e.api.regWrite, handle, "uc_reg_write")
	purego.RegisterLibFunc(&e.api.emuStart, handle, "uc_emu_start")
	purego.RegisterLibFunc(&e.api.emuStop, handle, "uc_emu_stop")
	purego.RegisterLibFunc(&e.api.hookAdd, handle, "uc_hook_add")
	purego.RegisterLibFunc(&e.api.hookDel, handle, "uc_hook_del")
}

func (e *Engine) MemMap(address, size uint64) error {
	handle, done, err := e.beginOperation()
	if err != nil {
		return err
	}

	defer done()

	if err := e.err(e.api.memMap(handle, address, size, protAll)); err != nil {
		return err
	}

	e.regionsMu.Lock()
	e.regions = append(e.regions, mappedRegion{start: address, end: address + size})
	e.regionsMu.Unlock()

	return nil
}

// FlushTranslations drops every TLB entry and translation block.
//
// uc_mem_map registers the region but does not invalidate the translations cached
// for it, so on the TCI build a page can read back fine through uc_mem_read --
// which goes straight to physical memory -- while the guest still faults on it.
// uc_ctl(UC_CTL_TLB_FLUSH) is the only entry point that forces the cache out;
// uc_mem_protect does not touch it.
func (e *Engine) FlushTranslations() error {
	handle, done, err := e.beginOperation()
	if err != nil {
		return err
	}

	defer done()

	// UC_CTL_WRITE(UC_CTL_TLB_FLUSH, 0) = 12 | (1 << 30).
	const tlbFlush = 12 | (1 << 30)

	return e.err(e.api.ctl(handle, tlbFlush, 0))
}

// MemProtect reapplies protection over a range. Even when the protection is
// unchanged this flushes the translation caches for that range, which is the
// only way to force a stale softmmu entry out on the TCI build.
func (e *Engine) MemProtect(address, size uint64, prot uint32) error {
	handle, done, err := e.beginOperation()
	if err != nil {
		return err
	}

	defer done()

	return e.err(e.api.memProtect(handle, address, size, prot))
}

func (e *Engine) MemUnmap(address, size uint64) error {
	handle, done, err := e.beginOperation()
	if err != nil {
		return err
	}

	defer done()

	return e.err(e.api.memUnmap(handle, address, size))
}

func (e *Engine) MemRead(address, size uint64) ([]byte, error) {
	handle, done, err := e.beginOperation()
	if err != nil {
		return nil, err
	}
	defer done()

	data := make([]byte, size)
	if len(data) == 0 {
		return data, nil
	}

	err = e.err(e.api.memRead(handle, address, unsafe.Pointer(&data[0]), size))

	return data, err
}

func (e *Engine) MemReadInto(data []byte, address uint64) error {
	handle, done, err := e.beginOperation()
	if err != nil {
		return err
	}
	defer done()

	if len(data) == 0 {
		return nil
	}

	return e.err(e.api.memRead(handle, address, unsafe.Pointer(&data[0]), uint64(len(data))))
}

func (e *Engine) MemWrite(address uint64, data []byte) error {
	handle, done, err := e.beginOperation()
	if err != nil {
		return err
	}
	defer done()

	if len(data) == 0 {
		return nil
	}

	return e.err(e.api.memWrite(handle, address, unsafe.Pointer(&data[0]), uint64(len(data))))
}

func (e *Engine) RegRead(register int) (uint64, error) {
	handle, done, err := e.beginOperation()
	if err != nil {
		return 0, err
	}
	defer done()

	var value uint64
	err = e.err(e.api.regRead(handle, int32(register), unsafe.Pointer(&value)))

	return value, err
}

func (e *Engine) RegWrite(register int, value uint64) error {
	handle, done, err := e.beginOperation()
	if err != nil {
		return err
	}

	defer done()

	return e.err(e.api.regWrite(handle, int32(register), unsafe.Pointer(&value)))
}

func (e *Engine) RegRead128(register int) ([16]byte, error) {
	handle, done, err := e.beginOperation()
	if err != nil {
		return [16]byte{}, err
	}
	defer done()

	var value [16]byte
	err = e.err(e.api.regRead(handle, int32(register), unsafe.Pointer(&value[0])))

	return value, err
}

func (e *Engine) RegWrite128(register int, value [16]byte) error {
	handle, done, err := e.beginOperation()
	if err != nil {
		return err
	}
	defer done()

	return e.err(e.api.regWrite(handle, int32(register), unsafe.Pointer(&value[0])))
}

// applyThreadPointer installs the configured TLS address in both thread pointer
// registers. Called with the operation already begun, so it writes through the
// same handle the emulation that follows will use.
func (e *Engine) applyThreadPointer(handle uintptr) error {
	if e.threadPointer == 0 {
		return nil
	}

	value := e.threadPointer

	if err := e.err(e.api.regWrite(handle, RegTPIDR_EL0, unsafe.Pointer(&value))); err != nil {
		return fmt.Errorf("write TPIDR_EL0: %w", err)
	}

	if err := e.err(e.api.regWrite(handle, RegTPIDRRO_EL0, unsafe.Pointer(&value))); err != nil {
		return fmt.Errorf("write TPIDRRO_EL0: %w", err)
	}

	return nil
}

func (e *Engine) Start(begin, end uint64) error {
	handle, done, err := e.beginOperation()
	if err != nil {
		return err
	}

	defer done()

	if err := e.applyThreadPointer(handle); err != nil {
		return err
	}

	return e.err(e.api.emuStart(handle, begin, end, 0, 0))
}

func (e *Engine) StartBounded(begin, end uint64, timeout time.Duration, instructionLimit uint64) error {
	if timeout < 0 {
		return errors.New("unicorn timeout must not be negative")
	}

	// A zero timeout means "none". It is the preferred form here: Unicorn's
	// timeout is enforced by a QEMU timer, and the signer starts emulation often
	// enough that the timer's thread is a resource the process cannot always
	// afford -- the run ended in "qemu_thread_create: Resource temporarily
	// unavailable" after finishing most of its work. An instruction limit bounds
	// the same thing without a thread.
	var microseconds uint64

	if timeout > 0 {
		microseconds = uint64(timeout / time.Microsecond)
		if microseconds == 0 {
			microseconds = 1
		}
	}

	handle, done, err := e.beginOperation()
	if err != nil {
		return err
	}

	defer done()

	if err := e.applyThreadPointer(handle); err != nil {
		return err
	}

	emuStarts.Add(1)

	if err := e.err(e.api.emuStart(handle, begin, end, microseconds, instructionLimit)); err != nil {
		return err
	}

	if microseconds == 0 {
		return nil
	}

	var timedOut uint64
	if err := e.err(e.api.query(handle, queryTimeout, &timedOut)); err != nil {
		return fmt.Errorf("query Unicorn timeout: %w", err)
	}

	if timedOut != 0 {
		return fmt.Errorf("%w after %s", errTimeout, timeout)
	}

	return nil
}

// emuStarts counts how many times emulation has been started on this engine.
// Reported at the end of a run to tell a leak of QEMU resources from a one-off.
var emuStarts atomic.Uint64

// EmuStarts reports the number of emulation starts since the process began.
func EmuStarts() uint64 { return emuStarts.Load() }

func (e *Engine) Stop() error {
	handle, done, err := e.beginOperation()
	if err != nil {
		return err
	}

	defer done()

	return e.err(e.api.emuStop(handle))
}

func (e *Engine) Close() error {
	if e == nil {
		return nil
	}

	e.stateMu.Lock()
	if e.closing {
		done := e.closeDone
		e.stateMu.Unlock()
		<-done
		e.stateMu.Lock()
		err := e.closeErr
		e.stateMu.Unlock()

		return err
	}

	e.closing = true
	e.stateMu.Unlock()

	runtime.SetFinalizer(e, nil)
	e.active.Wait()
	e.clearCodeHooks()

	e.stateMu.Lock()
	handle := e.handle
	loadedLibrary := e.library
	e.handle = 0
	e.library = library{}
	e.stateMu.Unlock()

	var errs []error

	if handle != 0 {
		if err := e.err(e.api.close(handle)); err != nil {
			errs = append(errs, err)
		}
	}

	if loadedLibrary.handle != 0 {
		if err := loadedLibrary.close(); err != nil {
			errs = append(errs, err)
		}
	}

	closeErr := errors.Join(errs...)

	e.stateMu.Lock()
	e.closeErr = closeErr
	close(e.closeDone)
	e.stateMu.Unlock()

	return closeErr
}

func (e *Engine) beginOperation() (uintptr, func(), error) {
	if e == nil {
		return 0, nil, errEngineClosed
	}

	e.stateMu.Lock()
	defer e.stateMu.Unlock()

	if e.closing || e.handle == 0 {
		return 0, nil, errEngineClosed
	}

	e.active.Add(1)

	return e.handle, e.active.Done, nil
}

func (e *Engine) err(code int32) error {
	if code == 0 {
		return nil
	}

	message := "unknown error"
	if description := e.api.strerror(code); description != "" {
		message = description
	}

	return fmt.Errorf("unicorn error %d: %s", code, message)
}
