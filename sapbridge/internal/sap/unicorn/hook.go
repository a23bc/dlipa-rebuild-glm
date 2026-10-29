package unicorn

import (
	"errors"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/ebitengine/purego"
)

const hookCode = 1 << 2

// MemoryFaultHook is deliberately absent.
//
// The audit flagged its removal as a risk, on the theory that the arm64 path
// might depend on fault-then-map. It does not: upstream defines
// AddMemoryFaultHook, but the only caller is internal/store/profilegen, a
// host-side bootstrap VM that demand maps cache pages. internal/sap/machine --
// the arm64 path this app runs -- registers only a code hook and maps every
// region up front in machine.Open. Restoring it would add dead code that looks
// load-bearing, which is worse than its absence.

type CodeHook func(address uint64, size uint32)

type hookState struct {
	mu  sync.Mutex
	ids map[uintptr]struct{}
}

type Hook struct {
	mu     sync.Mutex
	engine *Engine
	// One Hook can stand for several uc_hook handles: an unmapped callback is
	// registered once per access kind, and Close has to delete every one of
	// them. Storing only the last left the other two installed, so unmapped
	// accesses kept entering a trampoline whose callback entry had already been
	// deleted.
	handles []uintptr
	id      uintptr
}

var (
	codeHookID         atomic.Uint64
	codeHookCallbacks  sync.Map
	codeHookTrampoline = purego.NewCallback(func(
		_ purego.CDecl,
		_ uintptr,
		address uint64,
		size uint32,
		userData uintptr,
	) uintptr {
		callback, ok := codeHookCallbacks.Load(userData)
		if ok {
			callback.(CodeHook)(address, size)
		}

		return 0
	})
)

// AddCodeHook registers callback for instructions whose start address is in
// the inclusive range [begin, end]. The callback is retained until the Hook or
// Engine is closed; it runs through a C ABI trampoline and must not panic.
func (e *Engine) AddCodeHook(begin, end uint64, callback CodeHook) (*Hook, error) {
	handle, done, err := e.beginOperation()
	if err != nil {
		return nil, err
	}

	defer done()

	if callback == nil {
		return nil, errors.New("unicorn code hook callback is nil")
	}

	id := uintptr(codeHookID.Add(1))
	if id == 0 {
		id = uintptr(codeHookID.Add(1))
	}

	codeHookCallbacks.Store(id, callback)

	var hookHandle uintptr
	if err := e.err(e.api.hookAdd(handle, &hookHandle, hookCode, codeHookTrampoline, id, begin, end)); err != nil {
		codeHookCallbacks.Delete(id)
		writeHookCallbacks.Delete(id)
		unmappedHookCallbacks.Delete(id)
		writeHookCallbacks.Delete(id)

		return nil, err
	}

	e.hooks.mu.Lock()
	if e.hooks.ids == nil {
		e.hooks.ids = make(map[uintptr]struct{})
	}

	e.hooks.ids[id] = struct{}{}
	e.hooks.mu.Unlock()

	return &Hook{engine: e, handles: []uintptr{hookHandle}, id: id}, nil
}

func (h *Hook) Close() error {
	if h == nil {
		return nil
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if h.engine == nil {
		return nil
	}

	engine := h.engine
	handle, done, err := engine.beginOperation()

	if err == nil {
		for _, hookHandle := range h.handles {
			if delErr := engine.err(engine.api.hookDel(handle, hookHandle)); delErr != nil && err == nil {
				err = delErr
			}
		}

		done()

		if err != nil {
			return err
		}
	} else if !errors.Is(err, errEngineClosed) {
		return err
	}

	codeHookCallbacks.Delete(h.id)
	writeHookCallbacks.Delete(h.id)
	unmappedHookCallbacks.Delete(h.id)
	writeHookCallbacks.Delete(h.id)
	engine.hooks.mu.Lock()
	delete(engine.hooks.ids, h.id)
	engine.hooks.mu.Unlock()

	h.engine = nil
	h.handles = nil
	h.id = 0

	return nil
}

func (e *Engine) clearCodeHooks() {
	e.hooks.mu.Lock()
	defer e.hooks.mu.Unlock()

	for id := range e.hooks.ids {
		codeHookCallbacks.Delete(id)
		writeHookCallbacks.Delete(id)
		unmappedHookCallbacks.Delete(id)
		writeHookCallbacks.Delete(id)
	}

	clear(e.hooks.ids)
}

const hookMemWrite = 1 << 11

// WriteHook reports a guest store into a watched range.
//
// It exists because the question "where did this value come from" sometimes has
// no answer in the code: signing stopped on a load through a global that held
// 0x200, the global is in AMS's bss, and the store that put it there is on one of
// the paths an obfuscated dispatcher chooses between. Watching the eight bytes
// answers it directly, and the pc is included so the answer is a location rather
// than another value to interpret.
type WriteHook func(address uint64, size uint32, value uint64, pc uint64)

type writeWatch struct {
	engine   *Engine
	callback WriteHook
}

var (
	writeHookID         atomic.Uint64
	writeHookCallbacks  sync.Map
	writeHookTrampoline = purego.NewCallback(func(
		_ purego.CDecl,
		handle uintptr,
		_ int32,
		address uint64,
		size uint32,
		value int64,
		userData uintptr,
	) uintptr {
		entry, ok := writeHookCallbacks.Load(userData)
		if !ok {
			return 0
		}

		entry.(writeWatch).deliver(handle, address, size, value)

		return 0
	})
)

// deliver reads the pc straight through the api rather than through RegRead, to
// keep a watched write from taking stateMu and touching the active counter. Not
// a deadlock: beginOperation releases the lock before it returns.
func (w writeWatch) deliver(handle uintptr, address uint64, size uint32, value int64) {
	var pc uint64

	_ = w.engine.api.regRead(handle, RegPC, unsafe.Pointer(&pc))

	w.callback(address, size, uint64(value), pc)
}

// AddWriteWatch registers callback for stores that touch [begin, end).
func (e *Engine) AddWriteWatch(begin, end uint64, callback WriteHook) (*Hook, error) {
	handle, done, err := e.beginOperation()
	if err != nil {
		return nil, err
	}

	defer done()

	if callback == nil {
		return nil, errors.New("unicorn write hook callback is nil")
	}

	id := uintptr(writeHookID.Add(1))
	if id == 0 {
		id = uintptr(writeHookID.Add(1))
	}

	writeHookCallbacks.Store(id, writeWatch{engine: e, callback: callback})

	var hookHandle uintptr
	if err := e.err(e.api.hookAdd(handle, &hookHandle, hookMemWrite, writeHookTrampoline, id, begin, end)); err != nil {
		writeHookCallbacks.Delete(id)

		return nil, err
	}

	e.hooks.mu.Lock()
	if e.hooks.ids == nil {
		e.hooks.ids = make(map[uintptr]struct{})
	}

	e.hooks.ids[id] = struct{}{}
	e.hooks.mu.Unlock()

	return &Hook{engine: e, handles: []uintptr{hookHandle}, id: id}, nil
}

const (
	hookMemReadUnmapped  = 1 << 4
	hookMemWriteUnmapped = 1 << 5
	hookMemFetchUnmapped = 1 << 6
)

// UnmappedHook reports an access to memory that is not mapped, and decides
// whether it was handled.
//
// Returning true tells Unicorn the fault is dealt with and the access is retried.
// A hook that maps the page before returning therefore gets execution moving
// again, which is the difference between discovering one missing page per run and
// discovering all of them in one.
type UnmappedHook func(address uint64, size uint32, fetch bool) bool

type unmappedWatch struct {
	callback UnmappedHook
}

var (
	unmappedHookID         atomic.Uint64
	unmappedHookCallbacks  sync.Map
	unmappedHookTrampoline = purego.NewCallback(func(
		_ purego.CDecl,
		_ uintptr,
		kind int32,
		address uint64,
		size uint32,
		_ int64,
		userData uintptr,
	) uintptr {
		entry, ok := unmappedHookCallbacks.Load(userData)
		if !ok {
			return 0
		}

		if entry.(unmappedWatch).callback(address, size, kind == hookMemFetchUnmapped) {
			return 1
		}

		return 0
	})
)

// AddUnmappedHook registers callback for unmapped accesses in [begin, end).
func (e *Engine) AddUnmappedHook(begin, end uint64, callback UnmappedHook) (*Hook, error) {
	handle, done, err := e.beginOperation()
	if err != nil {
		return nil, err
	}

	defer done()

	if callback == nil {
		return nil, errors.New("unicorn unmapped hook callback is nil")
	}

	id := uintptr(unmappedHookID.Add(1))
	if id == 0 {
		id = uintptr(unmappedHookID.Add(1))
	}

	unmappedHookCallbacks.Store(id, unmappedWatch{callback: callback})

	var handles []uintptr

	kinds := []int32{hookMemFetchUnmapped, hookMemReadUnmapped, hookMemWriteUnmapped}
	for _, kind := range kinds {
		var hookHandle uintptr

		if err := e.err(e.api.hookAdd(handle, &hookHandle, kind, unmappedHookTrampoline, id, begin, end)); err != nil {
			// Delete what was already registered rather than leaking it.
			for _, added := range handles {
				_ = e.api.hookDel(handle, added)
			}
			unmappedHookCallbacks.Delete(id)

			return nil, err
		}

		handles = append(handles, hookHandle)
	}

	e.hooks.mu.Lock()
	if e.hooks.ids == nil {
		e.hooks.ids = make(map[uintptr]struct{})
	}

	e.hooks.ids[id] = struct{}{}
	e.hooks.mu.Unlock()

	return &Hook{engine: e, handles: handles, id: id}, nil
}
