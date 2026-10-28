// Package emulator is the Objective-C runtime bridge for the pinned Store image.
package emulator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/a23bc/dlipa-rebuild/sapbridge/internal/sap/machimage"
	"github.com/a23bc/dlipa-rebuild/sapbridge/internal/sap/unicorn"
	"github.com/a23bc/dlipa-rebuild/sapbridge/internal/store/cachepages"
	storeprofile "github.com/a23bc/dlipa-rebuild/sapbridge/internal/store/profile"
	profileformat "github.com/a23bc/dlipa-rebuild/sapbridge/internal/store/profile/format"
	"github.com/blacktop/go-macho"
)

const heapBase = uint64(0x400000000000)
const heapSize = uint64(64 << 20)
const stackBase = uint64(0x500000000000)
const stackSize = uint64(8 << 20)
const returnPC = uint64(0x100000000)

type Method = profileformat.Method
type Class = profileformat.Class
type Call = profileformat.Call
type Page = profileformat.Page
type Constant = profileformat.Constant
type DictionaryLayout = profileformat.DictionaryLayout
type MetadataPatch = profileformat.MetadataPatch
type Profile = profileformat.Profile

type Object struct {
	Class      string
	Value      any
	Properties map[string]uint64
}
type timer struct{ at, block uint64 }
type taskLocalBinding struct{ key, value uint64 }
type Runtime struct {
	lastResponse                             *http.Response
	transportError                           error
	streamResponse, noRedirects, authRequest bool

	taskLocalFrames             map[uint64][]taskLocalBinding
	transport                   func(*http.Request) (*http.Response, error)
	inflaters                   map[uint64]*inflateStream
	responseHeaders             map[uint64]http.Header
	tasks                       map[uint64]*asyncTask
	currentTask                 *asyncTask
	nullObject                  uint64
	associations                map[uint64]map[uint64]uint64
	currentQueue, selectedQueue uint64
	preferences                 map[string]uint64
	notificationCenter          uint64
	observers                   map[uint64]*Object
	pendingQueues               map[uint64]uint64
	allocations                 map[uint64]uint64
	ctx                         context.Context
	codeRanges                  [][2]uint64
	running                     bool
	symbolTrace                 []string
	symbolTraceLimit            int
	errnoCell                   uint64
	steps                       uint64
	timers                      []timer
	callbacks                   map[uint64]func()
	pending                     []uint64
	hardwareID                  []byte
	engine                      *unicorn.Engine
	ownsEngine                  bool
	profile                     Profile
	classes                     map[string]*Class
	classNames                  map[uint64]string
	methods                     map[string]uint64
	calls                       map[uint64]Call
	selectors                   map[uint64]string
	selectorAddresses           map[string]uint64
	objects                     map[uint64]*Object
	pages                       map[uint64]bool
	cachePages                  map[uint64]bool
	profilePages                map[uint64]bool
	cursor                      uint64
	fault                       error
	trace                       []string

	entries map[uint64]string
	hook    *unicorn.Hook
}

func Open(ctx context.Context, imageData []byte, prepared storeprofile.Data) (*Runtime, error) {
	return open(ctx, nil, imageData, prepared, 0, false)
}

// OpenWithEngine builds the runtime on top of an engine that already exists.
//
// The runtime does not own an injected engine and will not close it: on iOS there
// is one guest per process (roughly 173 MB, and a second cannot be created), so
// the engine is shared with the SAP path and outlives any single request. Close
// therefore releases the guest-side objects but leaves the machine running.
func OpenWithEngine(ctx context.Context, engine *unicorn.Engine, imageData []byte, prepared storeprofile.Data) (*Runtime, error) {
	if engine == nil {
		return nil, errors.New("emulator engine is nil")
	}

	return open(ctx, engine, imageData, prepared, 0, false)
}

// OpenWithEngineAt is OpenWithEngine for an engine whose heap already belongs to
// another guest.
//
// The SAP machine and this runtime share one 64 MB heap region, and the machine
// keeps allocating there whenever it signs. Handing the runtime the same low
// addresses means every object it creates lands on live session state -- and
// since allocations are now cleared, it erases it. heapUsed is how far the other
// tenant has got; the runtime starts past the halfway mark regardless, so the
// two cannot chase each other upward.
// openProbe is a guest address whose word is printed after each phase of open().
//
// Temporary. A single instruction differed from the page blob in the guest --
// `mov x1, x0` had become `ret` -- and no write hook saw it happen, so the stage
// that changes it has to be found by asking between stages rather than by
// guessing at writers. Zero disables it.
var openProbe uint64

// SetOpenProbe names the address open() should report after each phase.
func SetOpenProbe(address uint64) { openProbe = address }

// probeWord prints the word at the probe address, if one is set.
func (r *Runtime) probeWord(phase string) {
	if openProbe == 0 {
		return
	}

	word, err := r.engine.MemRead(openProbe, 4)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[SAP] probe %s: %#x unreadable: %v\n", phase, openProbe, err)

		return
	}

	fmt.Fprintf(os.Stderr, "[SAP] probe %s: %#x = %x\n", phase, openProbe, word)
}

func OpenWithEngineAt(ctx context.Context, engine *unicorn.Engine, imageData []byte, prepared storeprofile.Data, heapUsed uint64) (*Runtime, error) {
	if engine == nil {
		return nil, errors.New("emulator engine is nil")
	}

	return open(ctx, engine, imageData, prepared, heapUsed, false)
}

// open optionally guards accesses against the exported page set. Validation and
// production use the same grouped mappings to stay within Unicorn section limits.
func open(ctx context.Context, provided *unicorn.Engine, imageData []byte, prepared storeprofile.Data, heapUsed uint64, strict bool) (*Runtime, error) {
	if ctx == nil {
		return nil, errors.New("emulator context is nil")
	}

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("prepare store runtime: %w", err)
	}

	// Upstream compares sha256(imageData) with a pinned digest here. That can
	// never pass on iOS: MobileInstallation re-signs Mach-O files in the app
	// bundle at install time, appending a code-signature blob and changing both
	// the size and the digest. Only the blob changes -- the segments the profile
	// addresses refer to are untouched, which is why the SAP path already runs on
	// these bytes.
	//
	// assets.validate() documents the same thing and skips the digest by default
	// on this platform, keeping it behind DSH_SAP_VERIFY=1. This check follows
	// that precedent rather than inventing a second policy.
	if os.Getenv("DSH_SAP_VERIFY") == "1" {
		if fmt.Sprintf("%x", sha256.Sum256(imageData)) != "95f4558aa2c0ccd9f96ed479e336b630b46bf4b4e0baabc1c1ac8c7d55e21ab4" {
			return nil, errors.New("AppleMediaServices does not match the pinned 26A434 image")
		}
	}

	metadata, err := cachedMetadata.load(ctx, prepared.Metadata)
	if err != nil {
		return nil, fmt.Errorf("prepare store runtime: %w", err)
	}

	profile := metadata.profile

	imageInputs := map[string][]byte{"AppleMediaServices": imageData}

	if profile.PluginUUID != "" {
		if profile.PluginUUID != "B8C07F94-4868-3CD7-A59A-F01E8C24C1B7" {
			return nil, errors.New("unsupported authentication plugin UUID")
		}

		plugin := prepared.Plugin
		if fmt.Sprintf("%x", sha256.Sum256(plugin)) != "e33fff05a6e6593dd91e33fd103b5d3068b62a787c680df33b859f19b3acc4ea" {
			return nil, errors.New("authentication plugin does not match the pinned image")
		}

		imageInputs["AMSAccountAuthenticationPlugin"] = plugin
	}

	engine := provided
	ownsEngine := provided == nil

	if engine == nil {
		var err error
		engine, err = unicorn.New(ctx)
		if err != nil {
			return nil, fmt.Errorf("prepare store runtime: %w", err)
		}
	}

	r := metadata.newRuntime()
	r.engine = engine
	r.ownsEngine = ownsEngine
	r.ctx = ctx
	r.callbacks = map[uint64]func(){}
	ready := false

	defer func() {
		if !ready {
			_ = r.Close()
		}
	}()

	// Evidence for the reuse below: a non-zero head means the SAP machine has
	// already been here, and every allocation has to be cleared before use.
	if head, readErr := r.engine.MemRead(heapBase, 64); readErr == nil {
		fmt.Fprintf(os.Stderr, "[SAP] open(): heap head before reuse: %x\n", head)
	}

	for _, region := range [][2]uint64{{heapBase, heapSize}, {stackBase, stackSize}, {returnPC, 4096}} {
		if err = r.MemMap(region[0], region[1]); err != nil {
			// On iOS the SAP machine and the Store runtime share one guest, and
			// both put the return stub and the stack at the same fixed
			// addresses. Mapping a live region again fails with UC_ERR_MAP, so a
			// region that is already readable is reused instead of aborting.
			// Upstream never meets this: it always builds a fresh engine.
			if _, readErr := r.engine.MemRead(region[0], 1); readErr == nil {
				fmt.Fprintf(os.Stderr, "[SAP]   region %#x already mapped, reusing\n", region[0])

				continue
			}

			return nil, fmt.Errorf("prepare store runtime: %w", err)
		}
	}

	// The heap is shared with whichever guest mapped it first. Starting at the
	// bottom would hand out its live data, and every allocation is cleared now,
	// so that data would be erased. Half the heap each, and never below where the
	// other tenant has already got to.
	floor := heapUsed
	if floor < heapSize/2 {
		floor = heapSize / 2
	}

	floor = (floor + 15) &^ 15
	if floor > heapSize/2 {
		fmt.Fprintf(os.Stderr, "[SAP] open(): the other guest has used %d MB of the shared heap\n", floor>>20)
	}

	r.cursor = floor

	fmt.Fprintf(os.Stderr, "[SAP] open(): store heap starts at +%#x of %d MB (other guest used %#x)\n",
		floor, heapSize>>20, heapUsed)

	type textRange struct {
		name        string
		start, size uint64
	}

	var textRanges []textRange

	var imageSpans [][2]uint64

	for name, data := range imageInputs {
		fmt.Fprintf(os.Stderr, "[SAP] open(): machimage.Open %s with %d bytes\n", name, len(data))
		image, e := machimage.Open(name, data)
		if e != nil {
			return nil, fmt.Errorf("prepare store runtime: %w", e)
		}

		if e = image.PreparePrelinked(nil, func(symbol string) (uint64, error) { return 0, fmt.Errorf("unexpected relocation %s", symbol) }); e != nil {
			return nil, fmt.Errorf("prepare store runtime: %w", e)
		}

		// Read the instruction sections before Load drops i.file to free the asset
		// bytes; afterwards the Mach-O is gone and the sections cannot be read.
		for _, sec := range image.TextSections() {
			textRanges = append(textRanges, textRange{name: name, start: sec[0], size: sec[1]})
		}

		// Collected before Load, which drops the segment table along with the
		// file. The cache pages below must not land on any of these ranges.
		imageSpans = append(imageSpans, image.Spans()...)

		if e = image.Load(r); e != nil {
			return nil, fmt.Errorf("prepare store runtime: %w", e)
		}

	}

	r.probeWord("after images")

	// The profile's prepared pages point into the dyld shared cache, which the host
	// had mapped and the guest does not. Bring in the pages those pointers
	// reference before writing the profile's own pages, or every absolute pointer
	// into the cache lands on nothing.
	cachePages, err := cachepages.Load()
	if err != nil {
		return nil, fmt.Errorf("prepare store runtime: %w", err)
	}

	// The blob also carries pages that belong to the images this runtime just
	// loaded, because a system framework lives in the shared cache. Mapping those
	// is worse than useless: Load wrote that memory with its fixups applied, and
	// the cache copy still holds them encoded, so writing it back turns every
	// pointer in the segment into an address that means nothing.
	cachePages, dropped := cachepages.WithoutSpans(cachePages, imageSpans)

	// Mapping one page at a time inserts one region per call; contiguous pages
	// share a mapping instead.
	cacheStart := time.Now()
	runs := cachepages.Runs(cachePages)

	var stripped int

	for _, run := range runs {
		// The blob is a slice of the real shared cache, built for Apple silicon,
		// so its code carries PAuth and RCpc instructions this CPU cannot
		// execute. The SAP machine signs by calling into these pages -- the
		// first ldapr it met aborted the signature -- so they have to be
		// rewritten before anything runs from them.
		stripped += machimage.StripPAC(run.Data)

		if err = r.MemMap(run.Address, uint64(len(run.Data))); err != nil {
			return nil, fmt.Errorf("prepare store runtime: map cache run %#x: %w", run.Address, err)
		}

		if err = r.MemWrite(run.Address, run.Data); err != nil {
			return nil, fmt.Errorf("prepare store runtime: write cache run %#x: %w", run.Address, err)
		}

		// Remembered so a fault can say whether the missing page was in
		// this blob at all, rather than only that it is unmapped now.
		if r.cachePages == nil {
			r.cachePages = map[uint64]bool{}
		}

		for offset := 0; offset < len(run.Data); offset += 4096 {
			r.cachePages[run.Address+uint64(offset)] = true
		}
	}

	if len(cachePages) > 0 {
		fmt.Fprintf(os.Stderr, "[SAP] open(): mapped %d shared-cache pages in %d runs, %d ms (%d dropped: inside a loaded image, %d instructions rewritten)\n",
			len(cachePages), len(runs), time.Since(cacheStart).Milliseconds(), dropped, stripped)
	}

	r.probeWord("after cache pages")

	pageData := prepared.Pages
	addresses := make([]uint64, 0, len(profile.Pages))

	for _, page := range profile.Pages {
		if !r.pages[page.Address] {
			addresses = append(addresses, page.Address)
		}
	}

	fmt.Fprintf(os.Stderr, "[SAP] open(): %d recorded call sites, %d with symbols\n",
		len(r.calls), countSymbols(r.calls))

	for _, call := range profile.Calls {
		page := call.Address &^ 4095
		if !r.pages[page] {
			addresses = append(addresses, page)
		}
	}

	// The upstream strict branch calls engine.GuardMemory here. It is reachable
	// only from the package's own profile-validation tests -- production Open
	// passes strict=false -- so it is omitted rather than ported. That keeps this
	// fork from having to touch the engine at all, which matters because the SAP
	// path already works on the same engine kbsync uses.
	_ = strict

	regions, err := groupPages(addresses)
	if err != nil {
		return nil, fmt.Errorf("prepare store runtime: %w", err)
	}

	for _, region := range regions {
		if err = ctx.Err(); err != nil {
			return nil, fmt.Errorf("prepare store runtime: %w", err)
		}

		if err = r.MemMap(region.address, region.size); err != nil {
			return nil, fmt.Errorf("prepare store runtime: %w", err)
		}
	}

	for _, page := range profile.Pages {
		if page.Offset+4096 > uint64(len(pageData)) {
			return nil, errors.New("profile page exceeds data")
		}

		if err = r.MemWrite(page.Address, pageData[page.Offset:page.Offset+4096]); err != nil {
			return nil, fmt.Errorf("prepare store runtime: %w", err)
		}

		// MemMap records every range it maps, cache pages included, so the
		// profile's own pages are tracked separately for the fault report.
		if r.profilePages == nil {
			r.profilePages = map[uint64]bool{}
		}

		r.profilePages[page.Address&^0xFFF] = true
	}

	for _, call := range profile.Calls {
		page := call.Address &^ 4095

		// A recorded call is patched to `ret` because its implementation lives on
		// the host and cannot be recreated here. That `ret` is not a fallback: it
		// is the return half of the mechanism. The code hook fires at this
		// address first, dispatches to the Go implementation by symbol name and
		// sets x0; the guest then executes the `ret` and returns to its caller.
		//
		// Removing it -- which an earlier change did, one address at a time --
		// sends the guest into the real library body instead. For 0x180675ce8
		// that is libsystem_malloc, which needs zone state this runtime has no
		// way to build.
		if !r.pages[page] {
			if err = r.MemMap(page, 4096); err != nil {
				return nil, fmt.Errorf("prepare store runtime: %w", err)
			}
		}

		if err = r.MemWrite(call.Address, []byte{0xc0, 0x03, 0x5f, 0xd6}); err != nil {
			return nil, fmt.Errorf("prepare store runtime: %w", err)
		}
	}
	// Non-fragile ivar offsets are fixed by the Objective-C loader on macOS.
	// The profile's prepared pages are a snapshot of a real process, so they carry
	// the original pointer-authentication instructions and undo the stripping done
	// when each image was loaded. The emulated CPU has no PAuth and raises
	// UC_ERR_EXCEPTION on an autib, so strip again inside the guest.
	for _, tr := range textRanges {
		const chunk = 64 << 10

		var replaced int

		for off := uint64(0); off < tr.size; off += chunk {
			n := uint64(chunk)
			if off+n > tr.size {
				n = tr.size - off
			}

			b, readErr := r.engine.MemRead(tr.start+off, n)
			if readErr != nil {
				return nil, fmt.Errorf("prepare store runtime: read %s text: %w", tr.name, readErr)
			}

			changed := machimage.StripPAC(b)
			if changed == 0 {
				continue
			}

			if writeErr := r.engine.MemWrite(tr.start+off, b); writeErr != nil {
				return nil, fmt.Errorf("prepare store runtime: write %s text: %w", tr.name, writeErr)
			}

			replaced += changed
		}

		fmt.Fprintf(os.Stderr, "[SAP] open(): PAC strip %s: %d replaced over %#x+%#x\n", tr.name, replaced, tr.start, tr.size)
	}

	for _, imageBytes := range imageInputs {
		file, err := macho.NewFile(bytes.NewReader(imageBytes))
		if err != nil {
			return nil, fmt.Errorf("prepare store runtime: %w", err)
		}

		defer file.Close()

		for _, section := range file.Sections {
			if section.Flags.IsPureInstructions() || section.Flags.IsSomeInstructions() {
				r.codeRanges = append(r.codeRanges, [2]uint64{section.Addr, section.Addr + section.Size})
			}
		}

		if file.Symtab != nil {
			for _, sym := range file.Symtab.Syms {
				if !strings.HasPrefix(sym.Name, "_OBJC_IVAR_$_") {
					continue
				}

				parts := strings.SplitN(strings.TrimPrefix(sym.Name, "_OBJC_IVAR_$_"), ".", 2)
				if len(parts) != 2 {
					continue
				}

				if c := r.classes[parts[0]]; c != nil {
					if offset, ok := c.Ivars[parts[1]]; ok {
						data := make([]byte, 4)
						binary.LittleEndian.PutUint32(data, uint32(offset))

						if err = r.MemWrite(sym.Value, data); err != nil {
							return nil, fmt.Errorf("prepare store runtime: %w", err)
						}
					}
				}
			}
		}
	}

	for _, patch := range profile.MetadataPatches {
		if e := r.MemWrite(patch.Address, patch.Data); e != nil {
			return nil, fmt.Errorf("prepare store runtime: %w", e)
		}
	}

	r.hook, err = engine.AddCodeHook(0, ^uint64(0), r.step)
	if err != nil {
		return nil, fmt.Errorf("prepare store runtime: %w", err)
	}

	ready = true

	return r, nil
}
func methodKey(class, selector string, meta bool) string {
	prefix := "-"
	if meta {
		prefix = "+"
	}

	return prefix + "[" + class + " " + selector + "]"
}
func (r *Runtime) Close() error {
	if r.engine == nil {
		return nil
	}
	// Guest objects live for one request. Release their host references on close.
	clear(r.objects)
	clear(r.callbacks)
	clear(r.responseHeaders)
	clear(r.inflaters)
	clear(r.preferences)
	clear(r.associations)
	clear(r.observers)
	clear(r.tasks)
	r.pending = nil
	r.timers = nil
	// An injected engine belongs to the caller and must stay running.
	var err error
	if r.ownsEngine {
		err = r.engine.Close()
	}

	r.engine = nil

	if err != nil {
		return fmt.Errorf("close store runtime: %w", err)
	}

	return nil
}
func (r *Runtime) MemMap(address, size uint64) error {
	overlap := false
	for page := address; page < address+size; page += 4096 {
		overlap = overlap || r.pages[page]
	}

	// Watch the range that faults during encoder initWithBag: every map that
	// touches it is logged, because no MemUnmap exists anywhere in this package
	// and the page is readable immediately before the call that faults on it.
	if address < 0x1a2b0000 && address+size > 0x1a2a0000 {
		fmt.Fprintf(os.Stderr, "[SAP] watch: MemMap %#x+%#x (fault page range)\n", address, size)
	}

	if !overlap {
		if err := r.engine.MemMap(address, size); err == nil {
			for page := address; page < address+size; page += 4096 {
				r.pages[page] = true
			}

			return nil
		}

		// A whole-range map fails if any part of the range already exists, and
		// r.pages only knows what this Runtime mapped. On iOS the SAP machine has
		// the same AppleMediaServices image mapped at the same base, so a range
		// that crosses one of its segments cannot be mapped in a single call even
		// when the rest is free. Fall back to page granularity: keep what is
		// already there, map the gaps. Upstream never meets this because it always
		// builds its own engine on an empty address space.
		if err := r.mapPerPage(address, size); err != nil {
			return fmt.Errorf("map guest memory: %w", err)
		}

		for page := address; page < address+size; page += 4096 {
			r.pages[page] = true
		}

		return nil
	}

	for page := address; page < address+size; {
		if r.pages[page] {
			page += 4096

			continue
		}

		end := page + 4096
		for end < address+size && !r.pages[end] {
			end += 4096
		}

		if err := r.engine.MemMap(page, end-page); err != nil {
			if perPage := r.mapPerPage(page, end-page); perPage != nil {
				return fmt.Errorf("map guest memory: %w", perPage)
			}
		}

		for ; page < end; page += 4096 {
			r.pages[page] = true
		}
	}

	return nil
}

// mapPerPage maps what is missing inside a range, one 4 KiB page at a time.
//
// A page that is already readable is left alone: on iOS it belongs to the SAP
// machine, which mapped the same image from the same bytes. Only the gaps are
// mapped fresh.
func (r *Runtime) mapPerPage(address, size uint64) error {
	var fresh int

	for page := address; page < address+size; page += 4096 {
		if _, err := r.engine.MemRead(page, 1); err == nil {
			continue
		}

		if err := r.engine.MemMap(page, 4096); err != nil {
			return fmt.Errorf("page %#x: %w", page, err)
		}

		fresh++
	}

	// Force the translation caches for this range to be rebuilt. uc_mem_read
	// reads physical memory directly and succeeds on a page the guest then faults
	// on, which means the translations still say "not present"; reapplying the
	// same protection is what makes Unicorn drop them.
	if err := r.engine.FlushTranslations(); err != nil {
		return fmt.Errorf("flush translations after %#x+%#x: %w", address, size, err)
	}

	fmt.Fprintf(os.Stderr, "[SAP]   region %#x+%#x mapped per page (%d new)\n", address, size, fresh)

	return nil
}

func (r *Runtime) MemWrite(address uint64, data []byte) error {
	if err := r.engine.MemWrite(address, data); err != nil {
		return fmt.Errorf("write guest memory: %w", err)
	}

	return nil
}

const zeroChunk = 4096

var zeroBlock [zeroChunk]byte

func (r *Runtime) alloc(size uint64) uint64 {
	if size > heapSize {
		panic("guest allocation exceeds heap budget")
	}

	size = (size + 15) &^ 15
	if size == 0 {
		size = 16
	}

	if size > heapSize-r.cursor {
		panic("guest heap exhausted")
	}

	address := heapBase + r.cursor

	r.cursor += size

	// The heap is shared with the SAP machine: open reuses the region it already
	// mapped, so this memory holds whatever the handshake left there. A bump
	// allocator that hands that back as a fresh object gives every ivar the
	// previous tenant's bytes, and the handshake's bytes are key material that
	// differs on every run. That is why an AMSProcessInfo reached copyWithZone:
	// with a receiver that was never a pointer.
	for offset := uint64(0); offset < size; offset += zeroChunk {
		length := size - offset
		if length > zeroChunk {
			length = zeroChunk
		}

		if err := r.MemWrite(address+offset, zeroBlock[:length]); err != nil {
			panic(fmt.Sprintf("clear guest allocation %#x: %v", address, err))
		}
	}

	if r.allocations == nil {
		r.allocations = map[uint64]uint64{}
	}

	r.allocations[address] = size

	return address
}
func (r *Runtime) read64(address uint64) uint64 {
	b, e := r.engine.MemRead(address, 8)
	if e != nil {
		panic(fmt.Sprintf("read guest pointer %#x: %v", address, e))
	}

	return binary.LittleEndian.Uint64(b)
}
func (r *Runtime) write64(address, value uint64) {
	var b [8]byte

	binary.LittleEndian.PutUint64(b[:], value)

	if e := r.MemWrite(address, b[:]); e != nil {
		panic(e)
	}
}
func (r *Runtime) arg(i int) uint64 {
	reg := unicorn.RegX0 + i

	if i >= 8 {
		sp, _ := r.engine.RegRead(unicorn.RegSP)

		return r.read64(sp + uint64(i-8)*8)
	}

	v, e := r.engine.RegRead(reg)
	if e != nil {
		panic(e)
	}

	return v
}

// countSymbols counts the recorded call sites that name a symbol.
func countSymbols(calls map[uint64]Call) int {
	n := 0

	for _, call := range calls {
		if call.Symbol != "" {
			n++
		}
	}

	return n
}

// DumpTrace prints the last methods and symbol calls the guest reached.
func (r *Runtime) DumpTrace() {
	if len(r.trace) == 0 {
		return
	}

	fmt.Fprintf(os.Stderr, "[SAP] trace: %d entries\n", len(r.trace))

	for _, line := range r.trace {
		fmt.Fprintf(os.Stderr, "[SAP] trace: %s\n", line)
	}
}

// Fault reports the last bridge failure recorded while guest code ran, if any.
func (r *Runtime) Fault() error { return r.fault }

// TraceSymbols keeps the last n calls that reach a recorded call site, each with
// the symbol name and the first three arguments.
//
// The first version printed the first n instead, and the first sixty-four were
// all objc_retain and friends, so the call that mattered never appeared. Keeping
// the tail and printing it after the attempt is the shape that cannot miss: the
// interesting call is always near the end.
//
// Bounded because this sits on the per-instruction hook.
func (r *Runtime) TraceSymbols(n int) {
	r.symbolTrace = make([]string, 0, n)
	r.symbolTraceLimit = n
}

// DumpSymbolTrace prints the buffered calls, oldest first.
func (r *Runtime) DumpSymbolTrace() {
	if r.symbolTraceLimit == 0 {
		return
	}

	// Printed even when empty: "no call sites at all" and "tracing was off" look
	// the same in a log otherwise, and they mean different things.
	fmt.Fprintf(os.Stderr, "[SAP] symbol: last %d call sites\n", len(r.symbolTrace))

	for _, line := range r.symbolTrace {
		fmt.Fprintf(os.Stderr, "[SAP] symbol: %s\n", line)
	}
}

func (r *Runtime) set(value uint64) {
	if e := r.engine.RegWrite(unicorn.RegX0, value); e != nil {
		panic(e)
	}
}
func (r *Runtime) cstring(address uint64) string {
	if address == 0 {
		return ""
	}

	if value, ok := r.selectors[address]; ok {
		return value
	}

	var b []byte

	for i := uint64(0); i < 16384; i++ {
		v, e := r.engine.MemRead(address+i, 1)
		if e != nil {
			panic(fmt.Sprintf("read C string %#x: %v", address, e))
		}

		if v[0] == 0 {
			return string(b)
		}

		b = append(b, v[0])
	}

	panic("unterminated guest string")
}
func (r *Runtime) selector(value string) uint64 {
	if addr := r.selectorAddresses[value]; addr != 0 {
		return addr
	}

	addr := r.alloc(uint64(len(value) + 1))
	if err := r.MemWrite(addr, append([]byte(value), 0)); err != nil {
		panic(err)
	}

	r.selectorAddresses[value] = addr
	r.selectors[addr] = value

	return addr
}
func (r *Runtime) New(class string, value any) uint64 {
	size := uint64(256)
	if c := r.classes[class]; c != nil {
		size = max(c.Size, 16)
	}

	address := r.alloc(size)
	obj := &Object{Class: class, Value: value, Properties: map[string]uint64{}}

	r.objects[address] = obj
	if c := r.classes[class]; c != nil {
		r.write64(address, c.Address)
	}

	return address
}
func (r *Runtime) SetIvar(object uint64, name string, value uint64) error {
	obj := r.objects[object]
	if obj == nil {
		return errors.New("unknown guest object")
	}

	for class := obj.Class; class != ""; {
		c := r.classes[class]
		if c == nil {
			break
		}

		if offset, ok := c.Ivars[name]; ok {
			r.write64(object+offset, value)

			return nil
		}

		class = c.Super
	}

	return fmt.Errorf("unknown ivar %s.%s", obj.Class, name)
}
func (r *Runtime) String(address uint64) string {
	if address == 0 {
		return ""
	}

	obj := r.objects[address]
	if obj == nil {
		panic(fmt.Sprintf("unknown string object %#x", address))
	}

	value, ok := obj.Value.(string)
	if !ok {
		panic(fmt.Sprintf("object %s is not a string", obj.Class))
	}

	return value
}
func (r *Runtime) lookup(class, selector string, meta bool) uint64 {
	for class != "" {
		if address := r.methods[methodKey(class, selector, meta)]; address != 0 {
			return address
		}

		c := r.classes[class]
		if c == nil {
			break
		}

		class = c.Super
	}

	return 0
}

//nolint:nonamedreturns // Panic recovery must return an error from the ABI boundary.
func (r *Runtime) Invoke(object uint64, selector string, args ...uint64) (result uint64, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = recoveredError("guest setup", p)
		}
	}()

	class, meta := r.classNames[object]
	if !meta {
		obj := r.objects[object]
		if obj == nil {
			return 0, fmt.Errorf("unknown receiver %#x for %s", object, selector)
		}

		class = obj.Class
	}

	entry := r.lookup(class, selector, meta)
	if entry == 0 {
		block := r.hostBlock(func() { r.message(object, selector, false) })
		entry = r.read64(block + 16)
	}

	arguments := append([]uint64{object, r.selector(selector)}, args...)

	return r.call(entry, arguments...)
}
func (r *Runtime) call(entry uint64, arguments ...uint64) (uint64, error) {
	var err error

	for i := 0; i < 8; i++ {
		var v uint64
		if i < len(arguments) {
			v = arguments[i]
		}

		if e := r.engine.RegWrite(unicorn.RegX0+i, v); e != nil {
			return 0, fmt.Errorf("write guest register: %w", e)
		}
	}

	sp := stackBase + stackSize - 4096
	for i := 8; i < len(arguments); i++ {
		r.write64(sp+uint64(i-8)*8, arguments[i])
	}

	_ = r.engine.RegWrite(unicorn.RegSP, sp)
	_ = r.engine.RegWrite(unicorn.RegLR, returnPC)
	r.fault = nil

	// The code hook is installed over the whole address space, and the engine is
	// shared with the SAP machine. Without this flag the hook also fires while
	// that machine runs -- for instance when Execute calls Sign -- and stops it
	// for executing outside this runtime's images, which is exactly what the SAP
	// machine is supposed to do.
	r.running = true
	defer func() { r.running = false }()

	// No wall-clock timeout: the instruction budget bounds the run, and the
	// timeout's QEMU timer thread is a resource this process ran out of.
	err = r.engine.StartBounded(entry, returnPC, 0, 20_000_000)

	if r.fault != nil {
		return 0, r.fault
	}

	pc, _ := r.engine.RegRead(unicorn.RegPC)
	if err != nil {
		lr, _ := r.engine.RegRead(unicorn.RegLR)

		return 0, fmt.Errorf("guest stopped at %#x from %#x: %w; recent=%v", pc, lr, err, r.trace)
	}

	if pc != returnPC {
		return 0, fmt.Errorf("instruction budget exhausted at %#x", pc)
	}

	value, err := r.engine.RegRead(unicorn.RegX0)
	if err != nil {
		return 0, fmt.Errorf("read guest return register: %w", err)
	}

	return value, nil
}
func (r *Runtime) step(address uint64, _ uint32) {
	// Dispatch first, whoever is driving. Call sites and callbacks are keyed by
	// address, so they are unambiguous on a shared engine -- and the guest that
	// needs them is often the other tenant: the SAP machine's Execute calls Sign,
	// which runs the Store signer's code, and a `ret` with nothing behind it
	// returns the caller's own argument. Gating dispatch on r.running did exactly
	// that: 13370 recorded call sites, malloc among them, and no interception
	// when it mattered.
	if r.dispatch(address) {
		return
	}

	// Everything below only means something while this runtime drives the guest:
	// it decides which addresses may execute at all.
	if !r.running {
		return
	}

	defer func() {
		if p := recover(); p != nil {
			r.fault = fmt.Errorf("guest bridge at %#x: %w; back=%v; recent=%v",
				address, recoveredError("runtime", p), r.guestBacktrace(), r.trace)
			_ = r.engine.Stop()
		}
	}()

	// Not a recorded call site, so it has to be inside one of this runtime's
	// images. Anything else means the guest wandered off.
	allowed := false

	for _, region := range r.codeRanges {
		if address >= region[0] && address < region[1] {
			allowed = true

			break
		}
	}

	if !allowed {
		panic(fmt.Sprintf("execution outside the pinned image at %#x", address))
	}

	r.steps++
	if r.steps%4096 == 0 {
		if err := r.ctx.Err(); err != nil {
			panic(err)
		}
	}
}

// dispatch runs the host implementation for a callback or a recorded call site.
//
// It is keyed by address alone, so it does not care which tenant of the shared
// engine is driving -- and it must not: the Store signer's code is entered from
// the SAP machine's Execute, and gating this on r.running left every call site
// returning its own argument.
func (r *Runtime) dispatch(address uint64) bool {
	if callback := r.callbacks[address]; callback != nil {
		callback()

		return true
	}

	// The method ring is recorded here rather than in step() because the signer
	// runs under the SAP machine: gated on r.running it stayed empty exactly
	// during the calls worth seeing.
	if name := r.entries[address]; name != "" {
		receiver, _ := r.engine.RegRead(unicorn.RegX0)
		r.trace = append(r.trace, fmt.Sprintf("%s(recv=%#x)", name, receiver))
		if len(r.trace) > 32 {
			r.trace = r.trace[len(r.trace)-32:]
		}
	}

	call, ok := r.calls[address]
	if !ok {
		return false
	}

	// A host implementation that fails must surface as a fault on this runtime,
	// not as a panic through the Unicorn callback frame.
	//
	// It has to be printed here, not only stored: when the SAP machine is the one
	// driving, nobody reads r.fault -- the machine's own StartBounded sees the PC
	// no longer equals its return address and reports "stopped unexpectedly",
	// with no mention of the symbol that failed. One line here names it.
	defer func() {
		if p := recover(); p != nil {
			reason := recoveredError("runtime", p)
			r.fault = fmt.Errorf("guest bridge at %#x (%s): %w; back=%v; recent=%v",
				address, call.Symbol, reason, r.guestBacktrace(), r.trace)
			fmt.Fprintf(os.Stderr, "[SAP] bridge failed at %#x, symbol %q: %v\n", address, call.Symbol, reason)
			_ = r.engine.Stop()
		}
	}()

	if call.Selector != "" {
		r.message(r.arg(0), call.Selector, false)

		return true
	}

	if r.symbolTraceLimit > 0 {
		line := fmt.Sprintf("%s(x0=%#x x1=%#x x2=%#x)",
			strings.TrimLeft(call.Symbol, "_"), r.arg(0), r.arg(1), r.arg(2))

		if len(r.symbolTrace) == r.symbolTraceLimit {
			copy(r.symbolTrace, r.symbolTrace[1:])
			r.symbolTrace[len(r.symbolTrace)-1] = line
		} else {
			r.symbolTrace = append(r.symbolTrace, line)
		}
	}

	r.symbol(strings.TrimLeft(call.Symbol, "_"))

	return true
}

func (r *Runtime) jump(entry, receiver uint64, selector string) {
	_ = r.engine.RegWrite(unicorn.RegX0, receiver)
	_ = r.engine.RegWrite(unicorn.RegX1, r.selector(selector))
	_ = r.engine.RegWrite(unicorn.RegPC, entry)
}

func (r *Runtime) ClassAddress(name string) uint64 {
	if c := r.classes[name]; c != nil {
		return c.Address
	}

	return 0
}

// Export copies a Foundation value out of the guest without exposing guest pointers.
func (r *Runtime) Export(address uint64) (any, error) {
	return r.export(address, map[uint64]bool{}, 0)
}
func (r *Runtime) export(address uint64, active map[uint64]bool, depth int) (any, error) {
	if address == 0 {
		return nil, nil
	}

	if depth > 32 || active[address] {
		return nil, errors.New("cyclic or excessively nested guest value")
	}

	obj := r.objects[address]
	if obj == nil {
		return nil, fmt.Errorf("unknown exported object %#x", address)
	}

	active[address] = true
	defer delete(active, address)

	switch v := obj.Value.(type) {
	case map[string]uint64:
		result := map[string]any{}

		for k, p := range v {
			item, e := r.export(p, active, depth+1)
			if e != nil {
				return nil, e
			}

			result[k] = item
		}

		return result, nil
	case []uint64:
		result := make([]any, len(v))

		for i, p := range v {
			item, e := r.export(p, active, depth+1)
			if e != nil {
				return nil, e
			}

			result[i] = item
		}

		return result, nil
	default:
		return v, nil
	}
}

func (r *Runtime) queuePending(block, queue uint64) {
	if r.pendingQueues == nil {
		r.pendingQueues = map[uint64]uint64{}
	}

	r.pendingQueues[block] = queue
	r.pending = append(r.pending, block)
}
func (r *Runtime) nextPending() uint64 {
	for i, block := range r.pending {
		if q := r.objects[r.pendingQueues[block]]; q != nil && q.Properties["suspendCount"] != 0 {
			continue
		}

		r.pending = append(r.pending[:i], r.pending[i+1:]...)
		r.selectedQueue = r.pendingQueues[block]
		delete(r.pendingQueues, block)

		return block
	}

	return 0
}

func (r *Runtime) pendingCallback(block uint64, after func()) {
	previous := r.currentQueue
	r.currentQueue = r.selectedQueue
	r.callback(block, nil, func() { r.currentQueue = previous; after() })
}

func (r *Runtime) queueIsWithin(queue, target uint64) bool {
	for depth := 0; depth < 32; depth++ {
		if queue == target {
			return true
		}

		object := r.objects[queue]
		if object == nil {
			return false
		}

		queue = object.Properties["targetQueue"]
		if queue == 0 {
			return false
		}
	}

	panic("cyclic dispatch queue targets")
}

func recoveredError(stage string, value any) error {
	if cause, ok := value.(error); ok {
		return fmt.Errorf("%s: %w", stage, cause)
	}

	return fmt.Errorf("%s: %v", stage, value)
}
