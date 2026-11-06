// Package emulator is the Objective-C runtime bridge for the pinned Store image.
package emulator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/a23bc/dlipa-rebuild/sapbridge/internal/sap/machimage"
	"github.com/a23bc/dlipa-rebuild/sapbridge/internal/sap/unicorn"
	"github.com/a23bc/dlipa-rebuild/sapbridge/internal/store/cachepages"
	storeprofile "github.com/a23bc/dlipa-rebuild/sapbridge/internal/store/profile"
	profileformat "github.com/a23bc/dlipa-rebuild/sapbridge/internal/store/profile/format"
	"github.com/blacktop/go-macho"
)

// chunkLabel names one bucket of the map census by the span it covers, so the
// line reads as sizes rather than as bit counts. bits.Len64 files a value under
// the bucket whose floor is the power of two at or below it, which is exactly
// the 4 MiB / 2 MiB / ... boundary the mapping loop works against.
func chunkLabel(length int) string {
	span := uint64(1) << uint(length-1)
	if span < 1<<20 {
		return fmt.Sprintf("%d KiB", span>>10)
	}

	return fmt.Sprintf("%d MiB", span>>20)
}

// progressStep is the width of the census' second axis, and it is named here
// because the print divides the bucket index by it. The index comes from
// mappedInPhase rather than from a MiB count, and hard-coding the shift is how
// the first version of that line labelled 16 MiB steps as MiB -- a table whose
// numbers were right and whose axis was 16 times too small.
const progressStep = 16 << 20

// lazyCachePages decides how the shared-cache pages reach the guest: all of them
// mapped during open(), or indexed then handed out one at a time when the guest
// faults on them.
//
// It is a switch rather than a behaviour because the two are a bet on the same
// number -- the census prices mapping at about 0.8 s per MiB, so 38.8 MiB of
// shared cache costs 32.8 s every launch, while demand paging pays nothing up
// front and about 4 ms per page touched. Whoever touches less than half the
// cache wins; nobody has measured that yet, and this tree has already been
// wrong twice about which side of that line the guest is on. The lazy census
// printed after each run is the measurement that decides, which is why the
// switch ships before the default changes.
var lazyCachePages atomic.Bool

// SetLazyCachePages turns demand paging on or off. It has to be called before
// the store runtime opens: open() reads it once, and an already-open runtime
// has either mapped the cache or installed the hook, not both.
func SetLazyCachePages(on bool) { lazyCachePages.Store(on) }

// LazyCachePages reports the current setting, for a screen that has to say
// which of the two shapes its log lines will take.
func LazyCachePages() bool { return lazyCachePages.Load() }

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
	// deferFlush batches the translation-cache invalidation that follows a map.
	// Every map dropped the whole TLB and TB set: with twenty-five profile
	// regions that was twenty-five full flushes, and the phase that maps them
	// measured 63.6 s of a 131 s open. Callers that map in bulk set this and
	// flush once at the end.
	deferFlush bool

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
	// The indexed shared cache, live only when lazyCachePages is set: the
	// pages that can still be handed out, and the counters the census prints.
	// Everything here is written from the thread driving the engine -- the
	// unmapped hook runs inside emu_start, and so does the print at the end of
	// a run -- except the index itself, built in open() before any guest code
	// exists.
	lazyPages    map[uint64][]byte
	lazyHook     *unicorn.Hook
	lazyStripped int
	lazySkipped  int
	lazyTotal    int
	lazyFaults   uint64
	lazyBytes    uint64
	lazyMs       int64
	lazyAbsent   uint64
	lazyPrinted  uint64
	profilePages map[uint64]bool
	cursor       uint64
	fault        error
	trace        []string

	entries map[uint64]string
	hook    *unicorn.Hook
	// The four bytes each call site had before it was patched to `ret`.
	// The engine is shared: the SAP machine keeps running after Close, and a
	// `ret` where a real function used to be is not "closed", it is "still
	// patched". Close puts them back.
	patchedSites map[uint64][4]byte
	// Which shims have already been named for returning a host address.
	hostPointerSaid map[string]bool
	// Cast targets already reported as absent from the profile.
	castSaid map[uint64]bool
	// The address the last step was called for, so a guard that fires can say
	// which instruction branched to the bad target.
	lastPC uint64
	// Which host writes have already been reported, keyed by reason.
	hostWriteSaid map[string]bool
	// Set before the hook is removed, and read at the top of step. The hook has
	// to stay safe while it is being torn down, and a callback already past
	// Close would otherwise run against a nil engine.
	closed atomic.Bool
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
	// Phases are timed here rather than inferred from log timestamps: stderr is
	// drained in batches, so two lines a second apart on the clock can arrive
	// forty seconds apart, and every attribution made from those gaps was wrong.
	openStarted := time.Now()

	mark := func(label string) {
		fmt.Fprintf(os.Stderr, "[SAP] open(): phase %-12s at %s\n",
			label, time.Since(openStarted).Round(time.Millisecond))
	}

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

	skippedImages, skippedCachePages, skippedProfilePages := 0, 0, 0

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

		// The SAP machine loads AppleMediaServices before this runtime exists, and
		// runs the handshake in it. Loading the image again writes the pristine
		// __DATA over a running image and resets exactly the state a signer needs:
		// with the runtime closed, the same machine signs 354 bytes in 379 ms;
		// with it open, the same call returns nothing.
		sections := image.TextSections()
		if len(sections) > 0 && r.engine != nil && r.engine.IsMapped(sections[0][0], 1) {
			fmt.Fprintf(os.Stderr, "[SAP] open(): %s is already loaded at %#x, leaving it alone\n", name, sections[0][0])
			skippedImages++
		} else if e = image.Load(r); e != nil {
			return nil, fmt.Errorf("prepare store runtime: %w", e)
		}

	}

	r.probeWord("after images")

	r.logBagSlot("after images")

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

	// Two ways to get the shared cache into the guest. The census settled the
	// price of the first: mapping costs about 0.8 s per MiB of new bytes, no
	// matter how the bytes are chopped, so these 38.8 MiB cost the 32.8 s the
	// line below reports every launch. The second stops paying for pages the
	// guest never touches -- it indexes them and maps one when the guest faults
	// on it -- and the census printed after each run says how many of the 9,927
	// were actually asked for. That number is the whole argument for the extra
	// machinery, so it is printed whether the switch is on or off.
	if LazyCachePages() {
		if err = r.indexCachePages(runs); err != nil {
			return nil, fmt.Errorf("prepare store runtime: %w", err)
		}

		fmt.Fprintf(os.Stderr,
			"[SAP] open(): indexed %d shared-cache pages in %d runs, %d ms, mapped none (%d dropped: inside a loaded image, %d instructions rewritten)\n",
			len(r.lazyPages), len(runs), time.Since(cacheStart).Milliseconds(), dropped, r.lazyStripped)
	} else {
		if skippedCachePages, err = r.mapCachePages(runs, len(cachePages), dropped, skippedCachePages); err != nil {
			return nil, err
		}
	}

	mark("cache pages")

	r.probeWord("after cache pages")

	r.logBagSlot("after cache pages")

	pageData := prepared.Pages
	addresses := make([]uint64, 0, len(profile.Pages))

	for _, page := range profile.Pages {
		if !r.pages[page.Address] {
			addresses = append(addresses, page.Address)
		}
	}

	fmt.Fprintf(os.Stderr, "[SAP] open(): %d recorded call sites, %d with symbols\n",
		len(r.calls), countSymbols(r.calls))

	// The slot the encoder calls through, read once the pages are in place and
	// before anything runs. The profile has a guest address there; if this line
	// shows a host one, the loader put it there, and if it shows the guest
	// address then something overwrote it during the run -- two different bugs
	// that have been indistinguishable from the fault line alone.
	r.logBagSlot("after profile pages")

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

	mark("page table")

	regions, err := groupPages(addresses)
	if err != nil {
		return nil, fmt.Errorf("prepare store runtime: %w", err)
	}

	r.deferFlush = true

	var regionTime time.Duration

	// mapCell is one cell of the map-cost census: what a single uc_mem_map
	// covering this much address space cost, taken once this much had already
	// been mapped.
	//
	// It was written because the tree disagreed with itself about which axis
	// mattered: the comment in the loop below blamed big spans, the cache-pages
	// line read like a flat price per call, and the page loop right after this
	// one writes 40 MB in 13 ms. Running the same phase at 4 MiB and at 1 MiB
	// chunks settled it -- same rate per MiB, only the call count moved -- and
	// the conclusion now lives on that constant.
	//
	// Kept because it is the measurement any future change here has to be
	// judged against, and because the filter it replaced -- printing calls over
	// 200 ms -- hid 60 s of a 62 s phase from the log.
	type mapCell struct {
		count   int
		total   time.Duration
		worst   time.Duration
		samples []time.Duration
	}

	cells := map[[2]int]*mapCell{}

	var mappedInPhase uint64

	for _, region := range regions {
		if err = ctx.Err(); err != nil {
			return nil, fmt.Errorf("prepare store runtime: %w", err)
		}

		// One map per 4 MiB, which is what the phase costs either way.
		//
		// The census ran twice, once at this unit and once at 1 MiB, and the
		// two agree: 176 calls over 73.6 MiB in 62.2 s, and 230 calls over
		// 85.9 MiB in 65.8 s -- 844 ms per MiB against 766. Chopping the same
		// ground finer moved nothing but the call count, so neither "cost per
		// call" nor "cost superlinear in span" is true; the mapping price is
		// about 0.8 s per MiB of *newly mapped bytes*, and the cache-pages
		// phase above pays the same rate (38.8 MiB in 32.8 s). The whole of
		// open() is ~125 MiB at that rate, which is its measured 99 s.
		//
		// That makes this a constant with no lever in it, and it is why it is
		// left alone: the only thing that can shorten this phase is mapping
		// fewer bytes, not differently.
		const regionChunk = 4 << 20

		for offset := uint64(0); offset < region.size; offset += regionChunk {
			size := uint64(regionChunk)
			if offset+size > region.size {
				size = region.size - offset
			}

			regionMark := time.Now()

			if err = r.MemMap(region.address+offset, size); err != nil {
				return nil, fmt.Errorf("prepare store runtime: %w", err)
			}

			spent := time.Since(regionMark)
			regionTime += spent

			// The second key is MiB mapped by this phase so far, in 16 MiB
			// steps. It is a proxy for the engine's own region bookkeeping --
			// what the "grows with what is already there" hypothesis is about
			// -- and it starts with the phase, not with the process, so it
			// under-states the pressure the images and the cache pages already
			// put on it. Reading a fixed size down that row is still the test.
			key := [2]int{bits.Len64(size), int(mappedInPhase / progressStep)}

			cell := cells[key]
			if cell == nil {
				cell = &mapCell{}
				cells[key] = cell
			}

			cell.count++
			cell.total += spent
			cell.samples = append(cell.samples, spent)

			if spent > cell.worst {
				cell.worst = spent
			}

			mappedInPhase += size
		}
	}

	fmt.Fprintf(os.Stderr, "[SAP] open(): %d regions mapped in %s\n",
		len(regions), regionTime.Round(time.Millisecond))

	// The census, one line per cell used, ordered by span so a fixed size can be
	// read down the progress axis. Growing medians along a row mean the cost is
	// the bookkeeping of what is already mapped -- then mapping in a different
	// order, or once per arena instead of once per gap, is the lever. Flat rows
	// that rise with span mean bytes -- then only mapping less helps, which is
	// what the architecture document claims and this data exists to test.
	keys := make([][2]int, 0, len(cells))
	for key := range cells {
		keys = append(keys, key)
	}

	sort.Slice(keys, func(i, j int) bool {
		if keys[i][0] != keys[j][0] {
			return keys[i][0] < keys[j][0]
		}

		return keys[i][1] < keys[j][1]
	})

	for _, key := range keys {
		cell := cells[key]
		sort.Slice(cell.samples, func(i, j int) bool { return cell.samples[i] < cell.samples[j] })

		fmt.Fprintf(os.Stderr,
			"[SAP]   map census: %s at +%d MiB: n=%d total=%s median=%s worst=%s\n",
			chunkLabel(key[0]), key[1]*progressStep, cell.count,
			cell.total.Round(time.Millisecond),
			cell.samples[len(cell.samples)/2].Round(time.Millisecond),
			cell.worst.Round(time.Millisecond))
	}

	r.deferFlush = false

	// One flush for the whole batch, after every region is in place. uc_mem_read
	// reads physical memory directly and succeeds on a page the guest then faults
	// on, which is why the flush exists at all -- but it does not have to run
	// once per region.
	if err = r.engine.FlushTranslations(); err != nil {
		return nil, fmt.Errorf("prepare store runtime: flush translations: %w", err)
	}

	var (
		pending                       bool
		pendingAddress, pendingOffset uint64
		pendingPages                  int
		checkedStart                  uint64
		checkedData                   []byte
		// Where the seconds in this loop actually go. Two guesses at the cost
		// were both wrong -- batching the writes changed nothing measurable, and
		// chunking the reads changed nothing at all -- so it gets measured
		// instead of guessed a third time.
		probeCalls, readBytes         int
		timeProbe, timeRead, timeZero time.Duration
		timeWrite                     time.Duration
		iterations                    int
	)

	loopStarted := time.Now()

	for _, page := range profile.Pages {
		iterations++

		if page.Offset+4096 > uint64(len(pageData)) {
			return nil, errors.New("profile page exceeds data")
		}

		// A page that is already here came from the cache blob, which was read
		// out of the dyld cache file. The profile's copy was taken after the
		// store framework realized its Swift metadata, so for these pages the
		// profile is the newer of the two -- the opposite of what the cache rule
		// assumes, and the reason the encoder kept reading a page that shipped
		// as 4096 zeroes while the generator had 1512 nonzero bytes in it.
		//
		// The exception is a page the handshake wrote to: those are not zero and
		// must not be replaced. So an existing page is only overwritten when it
		// holds nothing at all.
		mark := time.Now()
		mapped := r.engine != nil && r.engine.IsMapped(page.Address, 4096)
		timeProbe += time.Since(mark)
		probeCalls++

		if mapped {
			// Read a chunk and answer for the pages inside it. One uc_mem_read
			// per page was 3,300 cross-cgo calls on device -- the same cost the
			// page-at-a-time mapping had, one layer down.
			const chunkPages = 16

			if checkedData == nil || page.Address < checkedStart ||
				page.Address+4096 > checkedStart+uint64(len(checkedData)) {
				size := uint64(chunkPages) * 4096

				readMark := time.Now()
				chunk, readErr := r.engine.MemRead(page.Address, size)
				if readErr != nil {
					// Short read near the end of a mapping: fall back to the page.
					chunk, readErr = r.engine.MemRead(page.Address, 4096)
				}

				if readErr != nil {
					skippedProfilePages++

					continue
				}

				timeRead += time.Since(readMark)
				readBytes += len(chunk)

				checkedStart, checkedData = page.Address, chunk
			}

			offset := page.Address - checkedStart
			current := checkedData[offset : offset+4096]

			zeroMark := time.Now()
			zero := allZero(current)
			timeZero += time.Since(zeroMark)

			if !zero {
				skippedProfilePages++

				continue
			}
		}

		// Consecutive pages go out in one write. The profile stores its pages in
		// address order, so most of these 1,900 arrive as a few dozen runs; one
		// MemWrite per run instead of per page is the difference between seconds
		// and minutes on device.
		if pending && page.Address == pendingAddress+4096 && page.Offset == pendingOffset+4096 {
			pendingPages++

			continue
		}

		if pending {
			writeMark := time.Now()

			if err = r.MemWrite(pendingAddress, pageData[pendingOffset:pendingOffset+uint64(pendingPages)*4096]); err != nil {
				return nil, fmt.Errorf("prepare store runtime: %w", err)
			}

			timeWrite += time.Since(writeMark)
		}

		pending = true
		pendingAddress, pendingOffset, pendingPages = page.Address, page.Offset, 1

		// MemMap records every range it maps, cache pages included, so the
		// profile's own pages are tracked separately for the fault report.
		if r.profilePages == nil {
			r.profilePages = map[uint64]bool{}
		}

		r.profilePages[page.Address&^0xFFF] = true
	}

	if pending {
		writeMark := time.Now()

		if err = r.MemWrite(pendingAddress, pageData[pendingOffset:pendingOffset+uint64(pendingPages)*4096]); err != nil {
			return nil, fmt.Errorf("prepare store runtime: %w", err)
		}

		timeWrite += time.Since(writeMark)
	}

	// total minus the parts: whatever is left is this loop's own bookkeeping --
	// the map insert, the run accumulator, the iteration itself. The parts add up
	// to 64 ms while the loop takes tens of seconds, so something outside them
	// owns the time and this line names it.
	accounted := timeProbe + timeRead + timeZero + timeWrite

	fmt.Fprintf(os.Stderr, "[SAP] open(): page loop iters=%d probes=%d read=%dKB total=%s (probe=%s read=%s zero=%s write=%s bookkeeping=%s)\n",
		iterations, probeCalls, readBytes/1024,
		time.Since(loopStarted).Round(time.Millisecond),
		timeProbe.Round(time.Millisecond), timeRead.Round(time.Millisecond),
		timeZero.Round(time.Millisecond), timeWrite.Round(time.Millisecond),
		(time.Since(loopStarted) - accounted).Round(time.Millisecond))

	// Once, after the loop. This line used to sit inside it, so a profile of
	// 1,790 pages printed 1,790 lines -- 1,790 writes through the black-box
	// recorder, each with its own lock and file I/O, and 1,790 lines for the log
	// view to lay out. On device that is minutes of a frozen screen for one
	// number that belongs in a single line.
	fmt.Fprintf(os.Stderr, "[SAP] open(): kept %d cache pages and %d profile pages the machine already had, skipped %d images\n",
		skippedCachePages, skippedProfilePages, skippedImages)

	// A recorded call is patched to `ret` because its implementation lives on the
	// host and cannot be recreated here. That `ret` is not a fallback: it is the
	// return half of the mechanism. The code hook fires at this address first,
	// dispatches to the Go implementation by symbol name and sets x0; the guest
	// then executes the `ret` and returns to its caller.
	//
	// Removing it -- which an earlier change did, one address at a time -- sends
	// the guest into the real library body instead. For 0x180675ce8 that is
	// libsystem_malloc, which needs zone state this runtime has no way to build.
	//
	// Done one page at a time: 13,370 call sites used to cost two uc_mem calls
	// each -- a read to save the original bytes and a write to patch -- and the
	// page is the natural unit for both. The patches for one page go into a
	// single buffer and land in one write.
	patchStarted := time.Now()

	byPage := make(map[uint64][]uint64, len(profile.Calls)/4)
	pageOrder := make([]uint64, 0, len(profile.Calls)/4)

	for _, call := range profile.Calls {
		page := call.Address &^ 4095
		if _, seen := byPage[page]; !seen {
			pageOrder = append(pageOrder, page)
		}

		byPage[page] = append(byPage[page], call.Address)
	}

	for _, page := range pageOrder {
		if !r.pages[page] {
			if err = r.MemMap(page, 4096); err != nil {
				return nil, fmt.Errorf("prepare store runtime: %w", err)
			}
		}

		data, readErr := r.engine.MemRead(page, 4096)
		if readErr != nil {
			return nil, fmt.Errorf("prepare store runtime: read page %#x: %w", page, readErr)
		}

		for _, address := range byPage[page] {
			offset := address - page

			if r.patchedSites == nil {
				r.patchedSites = make(map[uint64][4]byte, len(profile.Calls))
			}

			var saved [4]byte
			copy(saved[:], data[offset:offset+4])
			r.patchedSites[address] = saved

			copy(data[offset:offset+4], []byte{0xc0, 0x03, 0x5f, 0xd6})
		}

		if err = r.MemWrite(page, data); err != nil {
			return nil, fmt.Errorf("prepare store runtime: %w", err)
		}
	}

	mark("region maps")

	fmt.Fprintf(os.Stderr, "[SAP] open(): patched %d call sites across %d pages in %s\n",
		len(profile.Calls), len(pageOrder), time.Since(patchStarted).Round(time.Millisecond))
	mark("call sites")

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

	mark("pac strip")

	for _, patch := range profile.MetadataPatches {
		if e := r.MemWrite(patch.Address, patch.Data); e != nil {
			return nil, fmt.Errorf("prepare store runtime: %w", e)
		}
	}

	mark("metadata")

	r.hook, err = engine.AddCodeHook(0, ^uint64(0), r.step)
	if err != nil {
		return nil, fmt.Errorf("prepare store runtime: %w", err)
	}

	mark("hooks")

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

	// The hook is registered on the engine, and the engine is shared: it
	// outlives this runtime by design. Leaving the hook installed kept a Go
	// callback on every instruction after the diagnostic finished, and dispatch
	// kept finding call sites recorded here -- but r.engine was already nil, so
	// r.arg panicked, the panic was recovered into r.fault, and nothing on the
	// signer path reads that. The user saw "signing sometimes fails", long after
	// the diagnostic that caused it.
	r.closed.Store(true)

	var hookErr error

	if r.hook != nil {
		hookErr = r.hook.Close()
		r.hook = nil
	}

	if r.lazyHook != nil {
		if err := r.lazyHook.Close(); err != nil && hookErr == nil {
			hookErr = err
		}

		r.lazyHook = nil
	}

	// The index aliases the decoded blob: holding it keeps 47 MB of pages
	// resident for as long as anything could still be handed one.
	r.lazyPages = nil

	// Put the call sites back before anything else is cleared. Everything
	// after this point treats the engine as the SAP machine's again.
	var restoreErr error

	for address, original := range r.patchedSites {
		if writeErr := r.MemWrite(address, original[:]); writeErr != nil && restoreErr == nil {
			restoreErr = fmt.Errorf("restore call site %#x: %w", address, writeErr)
		}
	}

	r.patchedSites = nil
	clear(r.entries)
	clear(r.calls)
	r.codeRanges = nil

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

	if hookErr != nil {
		return fmt.Errorf("close store runtime hook: %w", hookErr)
	}

	if restoreErr != nil {
		return fmt.Errorf("close store runtime: %w", restoreErr)
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

	if !r.deferFlush {
		if err := r.engine.FlushTranslations(); err != nil {
			return fmt.Errorf("flush translations: %w", err)
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

	var (
		probeTime, mapTime time.Duration
		mapCalls           int
	)

	// One MemMap per run of missing pages, not one per page.
	//
	// The profile is a sparse table: 1,900 pages spread over a few dozen runs,
	// and mapping them one at a time cost minutes on device -- a single
	// 951-page region took 78 seconds. The gaps are what needs mapping; a page
	// that is already readable belongs to the other tenant and is skipped, so a
	// run only ever covers pages that are all missing.
	for page := address; page < address+size; {
		probeMark := time.Now()
		_, probeErr := r.engine.MemRead(page, 1)
		probeTime += time.Since(probeMark)

		if probeErr == nil {
			page += 4096

			continue
		}

		runStart := page

		for page < address+size {
			innerMark := time.Now()
			_, innerErr := r.engine.MemRead(page, 1)
			probeTime += time.Since(innerMark)

			if innerErr == nil {
				break
			}

			page += 4096
		}

		mapMark := time.Now()
		mapErr := r.engine.MemMap(runStart, page-runStart)
		mapTime += time.Since(mapMark)
		mapCalls++

		if mapErr != nil {
			return fmt.Errorf("map %#x+%#x: %w", runStart, page-runStart, mapErr)
		}

		fresh += int((page - runStart) / 4096)
	}

	fmt.Fprintf(os.Stderr, "[SAP]   region %#x+%#x mapped per page (%d new, %d maps, probe %s, map %s)\n",
		address, size, fresh, mapCalls,
		probeTime.Round(time.Millisecond), mapTime.Round(time.Millisecond))

	return nil
}

func (r *Runtime) MemWrite(address uint64, data []byte) error {
	// Unicorn's write hook does not fire for uc_mem_write, so anything this
	// program writes -- a page, a string, a return value -- is invisible to the
	// watch and to the shim check. The slot the encoder calls through ends up
	// holding a host address that appears in neither data blob, which leaves
	// exactly this path as the unexplained one.
	r.reportHostWrite(address, data)

	if err := r.engine.MemWrite(address, data); err != nil {
		return fmt.Errorf("write guest memory: %w", err)
	}

	return nil
}

// The slot the encoder loads a call target from. Named here because a write to
// it is worth a line even when the value looks ordinary.
const bagSlotAddress = 0x1e800c958

// reportHostWrite prints writes that carry a host-range qword, and any write to
// the bag slot regardless of its contents.
func (r *Runtime) reportHostWrite(address uint64, data []byte) {
	reason := ""

	if address <= bagSlotAddress && bagSlotAddress+8 <= address+uint64(len(data)) {
		reason = "bag slot"
	}

	if reason == "" {
		for offset := 0; offset+8 <= len(data); offset += 8 {
			value := uint64(0)
			for index := 7; index >= 0; index-- {
				value = value<<8 | uint64(data[offset+index])
			}

			if value >= hostPointerFloor && value < hostPointerCeiling {
				reason = "host qword"

				break
			}
		}
	}

	if reason == "" || r.hostWriteSaid[reason] {
		return
	}

	if r.hostWriteSaid == nil {
		r.hostWriteSaid = map[string]bool{}
	}

	r.hostWriteSaid[reason] = true

	fmt.Fprintf(os.Stderr, "[SAP] host write at %#x (%d bytes, %s): %x\n",
		address, len(data), reason, data[:min(len(data), 32)])
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

// allZero reports whether every byte is zero.
//
// Used to tell "the cache file had nothing here" from "something wrote here":
// only the former may be replaced by the profile's copy.
func allZero(data []byte) bool {
	for _, b := range data {
		if b != 0 {
			return false
		}
	}

	return true
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
	// Printed here rather than at Close: the store runtime is kept open for the	// life of the process, and the question -- how much of the cache did the	// guest actually touch -- is answered by the first download, not by quitting.	defer r.lazyCensus()

	// No wall-clock timeout: the instruction budget bounds the run, and the
	// timeout's QEMU timer thread is a resource this process ran out of.
	err = r.engine.StartBounded(entry, returnPC, 0, 20_000_000)

	if r.fault != nil {
		return 0, r.fault
	}

	pc, _ := r.engine.RegRead(unicorn.RegPC)
	if err != nil {
		lr, _ := r.engine.RegRead(unicorn.RegLR)

		// The registers the faulting instruction actually used: a load that
		// follows a register somewhere unmapped says nothing about where it got
		// the register, and the two answers -- a wild pointer, or a zero that was
		// never written -- need different fixes.
		x0, _ := r.engine.RegRead(unicorn.RegX0)
		x16, _ := r.engine.RegRead(unicorn.RegX16)
		x17, _ := r.engine.RegRead(unicorn.RegX0 + 17)

		return 0, fmt.Errorf("guest stopped at %#x from %#x: %w; x0=%#x x16=%#x x17=%#x recent=%v",
			pc, lr, err, x0, x16, x17, r.trace)
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
	if r.closed.Load() {
		return
	}

	previousPC := r.lastPC
	r.lastPC = address

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

	// The SAP machine's shims live in their own code area and the guest calls
	// them like any other function. This runtime drives the same engine and its
	// step hook runs first, so without this a call to ___chkstk_darwin reads as
	// "outside the pinned image" and the run stops -- which is exactly what the
	// 0x7ff880000340 fault was, for four rounds of diagnostics.
	//
	// The constants mirror machine/shims.go; they are duplicated rather than
	// imported because that package imports this one.
	const (
		shimBase = uint64(0x00007ff880000000)
		shimSize = uint64(0x0000000000080000)
	)

	if address >= shimBase && address < shimBase+shimSize {
		return
	}

	// Code also lives outside this runtime's images: the shared-cache pages the
	// profile points at carry whole functions, and the encoder's ent/download
	// path calls into them (0x1a8113350 was the first one it reached). The rule
	// is therefore "mapped and below the heap", not "inside a pinned image":
	// anything we mapped may execute, while a jump into the heap, the stack or
	// nothing at all is still a fault.
	//
	// The heap starts at 0x4000_0000_0000 and TLS at 0x6000_0000_0000; the shim
	// area above them is handled before this point.
	const heapBase = uint64(0x400000000000)

	if r.engine != nil && address < heapBase && r.engine.IsMapped(address, 4) {
		return
	}

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
		// The branch already happened, so the useful evidence is behind: which
		// instruction branched, and what the registers held. A `blr x8` and a
		// `ret` mean different things, and x8's value names the slot.
		// `blr x2` with x2=0 is what the registers show, yet the target is
		// 0x7ff880000340 -- so the value either arrived in a register we did not
		// print or the reads are one step behind the branch. Three instructions
		// back and every general register answers which.
		slot := r.reg(unicorn.RegX0 + 17)

		panic(fmt.Sprintf("execution outside the pinned image at %#x; from %#x; prev=[%s %s %s]; slot=[%#x]=%#x; regs %s sp=%#x lr=%#x",
			address, previousPC,
			r.instruction(previousPC-12), r.instruction(previousPC-8), r.instruction(previousPC-4),
			slot, r.quad(slot),
			r.registers(), r.reg(unicorn.RegSP), r.reg(unicorn.RegLR)))
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
			link, _ := r.engine.RegRead(unicorn.RegLR)
			fmt.Fprintf(os.Stderr, "[SAP] bridge failed at %#x, symbol %q: %v; lr=%#x recent=%v\n",
				address, call.Symbol, reason, link, r.trace)
			_ = r.engine.Stop()
		}
	}()

	if call.Selector != "" {
		r.message(r.arg(0), call.Selector, false)
		r.reportHostPointer(address, call.Symbol)

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
	r.reportHostPointer(address, call.Symbol)

	return true
}

// The guest jumped to 0x7ff880000340, which belongs to the host's address space
// rather than to any mapping this runtime creates. A value like that can only
// reach the guest through a return value from one of these shims, so naming the
// shim that produced one answers "who wrote that slot" directly instead of by
// inference from a backtrace.
const (
	hostPointerFloor   = 0x7f0000000000
	hostPointerCeiling = 0x800000000000
)

// instruction renders the four bytes at an address, or "?" when they cannot be
// read. Enough to tell blr from br from ret without symbolising.
func (r *Runtime) instruction(address uint64) string {
	if address == 0 {
		return "?"
	}

	word, err := r.engine.MemRead(address, 4)
	if err != nil || len(word) != 4 {
		return "?"
	}

	return fmt.Sprintf("%02x%02x%02x%02x", word[3], word[2], word[1], word[0])
}

// registers renders x0-x15 in one line; a single blr is unreadable without the
// register that carried the target.
func (r *Runtime) registers() string {
	// x16 and x17 are the scratch pair: `adrp x17 / add x17, x17, #imm /
	// ldr x16, [x17] / blr x16` is how a call through a table looks, and
	// stopping at x15 printed "blr x2 with x2=0" for exactly that sequence.
	parts := make([]string, 0, 19)
	for index := 0; index < 19; index++ {
		parts = append(parts, fmt.Sprintf("x%d=%#x", index, r.reg(unicorn.RegX0+index)))
	}

	return strings.Join(parts, " ")
}

// quad reads eight bytes, or 0 when the address cannot be read.
func (r *Runtime) quad(address uint64) uint64 {
	data, err := r.engine.MemRead(address, 8)
	if err != nil || len(data) != 8 {
		return 0
	}

	var value uint64
	for index := 7; index >= 0; index-- {
		value = value<<8 | uint64(data[index])
	}

	return value
}

// logBagSlot prints the call target the encoder will load, at a named stage.
//
// The writer cannot be caught -- it goes through none of the write paths this
// package can instrument -- so the value is read instead, once per stage. The
// stage that changes it is the answer.
func (r *Runtime) logBagSlot(stage string) {
	fmt.Fprintf(os.Stderr, "[SAP] open(): bag slot %s = %#x\n", stage, r.quad(bagSlotAddress))
}

func (r *Runtime) reg(register int) uint64 {
	value, err := r.engine.RegRead(register)
	if err != nil {
		return 0
	}

	return value
}

func (r *Runtime) reportHostPointer(address uint64, symbol string) {
	if r.hostPointerSaid == nil {
		r.hostPointerSaid = map[string]bool{}
	}

	for _, reg := range []int{unicorn.RegX0, unicorn.RegX1} {
		value, err := r.engine.RegRead(reg)
		if err != nil || value < hostPointerFloor || value >= hostPointerCeiling {
			continue
		}

		if r.hostPointerSaid[symbol] {
			continue
		}

		r.hostPointerSaid[symbol] = true

		fmt.Fprintf(os.Stderr, "[SAP] host pointer from %q at %#x: %#x\n",
			symbol, address, value)
	}
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

// unmappedPiece is a run of pages this runtime still has to map and write.
type unmappedPiece struct {
	address uint64
	data    []byte
}

// unmappedPieces splits a cache run into the stretches the engine does not
// already hold.
//
// The SAP machine maps pages long before this runtime opens and keeps changing
// them: globals it initialises, allocations it makes. The blob is a snapshot
// taken before that work, so writing it back over those pages undoes it. Pages
// the engine already has are left exactly as they are.
func unmappedPieces(r *Runtime, address uint64, data []byte) []unmappedPiece {
	if r.engine == nil {
		return []unmappedPiece{{address: address, data: data}}
	}

	var pieces []unmappedPiece

	start := -1

	for offset := 0; offset < len(data); offset += 4096 {
		page := address + uint64(offset)
		mapped := r.engine.IsMapped(page, 4096)

		switch {
		case mapped && start >= 0:
			pieces = append(pieces, unmappedPiece{address: address + uint64(start), data: data[start:offset]})
			start = -1
		case !mapped && start < 0:
			start = offset
		}
	}

	if start >= 0 {
		pieces = append(pieces, unmappedPiece{address: address + uint64(start), data: data[start:]})
	}

	return pieces
}

// mapCachePages brings the shared-cache blob into the guest up front: rewrite
// the instructions this CPU cannot execute, skip the pages another tenant
// already holds, and map the rest in contiguous runs.
//
// The runs are the point of the loop -- 3,833 individual maps would each
// invalidate every translation in the engine -- and the mapping is what the
// census priced at about 0.8 s per MiB, which is why this costs the launch
// 32.8 s whatever unit the bytes are chopped into.
func (r *Runtime) mapCachePages(runs []cachepages.Run, pages, dropped, skipped int) (int, error) {
	// Same batching as the profile regions.
	r.deferFlush = true

	start := time.Now()

	var stripped int

	for _, run := range runs {
		// The blob is a slice of the real shared cache, built for Apple silicon,
		// so its code carries PAuth and RCpc instructions this CPU cannot
		// execute. The SAP machine signs by calling into these pages -- the
		// first ldapr it met aborted the signature -- so they have to be
		// rewritten before anything runs from them.
		stripped += machimage.StripPAC(run.Data)

		// Pages the machine already mapped hold the machine's values, which are
		// newer than the blob's. Writing the blob back would undo whatever the
		// handshake initialised.
		pieces := unmappedPieces(r, run.Address, run.Data)

		total := 0
		for _, piece := range pieces {
			total += len(piece.data)
		}

		if total != len(run.Data) {
			skipped += (len(run.Data) - total) / 4096
		}

		for _, piece := range pieces {
			if err := r.MemMap(piece.address, uint64(len(piece.data))); err != nil {
				return skipped, fmt.Errorf("prepare store runtime: map cache run %#x: %w", piece.address, err)
			}

			if err := r.MemWrite(piece.address, piece.data); err != nil {
				return skipped, fmt.Errorf("prepare store runtime: write cache run %#x: %w", piece.address, err)
			}
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

	if len(runs) > 0 {
		r.deferFlush = false

		if err := r.engine.FlushTranslations(); err != nil {
			return skipped, fmt.Errorf("prepare store runtime: flush translations: %w", err)
		}

		fmt.Fprintf(os.Stderr, "[SAP] open(): mapped %d shared-cache pages in %d runs, %d ms (%d dropped: inside a loaded image, %d instructions rewritten)\n",
			pages, len(runs), time.Since(start).Milliseconds(), dropped, stripped)
	}

	return skipped, nil
}

// indexCachePages is the other half of the same money: prepare every page the
// guest might need without mapping any of it, then supply a page when the guest
// touches it.
//
// Stripping happens here, over the whole blob, because it is a pass over the
// bytes and not a mapping -- a few tens of ms against the 32.8 s the mapping
// costs -- and the page must be safe to execute the moment it is mapped. Pages
// another tenant already holds are left out of the index for the same reason
// the eager path skips writing them: the machine's copy is newer, and the blob
// would undo a live handshake.
//
// r.cachePages is filled at index time rather than at map time. It answers
// "was this address ever ours to give?", and a page still waiting in the index
// is exactly as much the answer as one already mapped.
func (r *Runtime) indexCachePages(runs []cachepages.Run) error {
	if r.lazyHook != nil {
		return errors.New("shared cache is already indexed")
	}

	r.lazyPages = map[uint64][]byte{}
	r.lazyTotal = 0

	if r.cachePages == nil {
		r.cachePages = map[uint64]bool{}
	}

	for _, run := range runs {
		r.lazyStripped += machimage.StripPAC(run.Data)

		for offset := 0; offset < len(run.Data); offset += 4096 {
			page := run.Address + uint64(offset)

			data := run.Data[offset:min(offset+4096, len(run.Data))]
			if len(data) != 4096 || r.engine.IsMapped(page, 4096) {
				r.lazySkipped++

				continue
			}

			r.lazyPages[page] = data
			r.cachePages[page] = true
			r.lazyTotal++
		}
	}

	hook, err := r.engine.AddUnmappedHook(0, ^uint64(0), r.mapLazyPage)
	if err != nil {
		r.lazyPages = nil

		return fmt.Errorf("install the shared-cache fault hook: %w", err)
	}

	r.lazyHook = hook

	return nil
}

// mapLazyPage answers one unmapped access out of the indexed shared cache.
//
// Returning true tells Unicorn the fault is dealt with and the access is
// retried, so the guest never sees it; the page is deleted from the index first,
// which is what bounds the damage. If the same address faults again the retry
// did not fix it, and a second lookup miss takes the old path -- the fault is
// reported with the "was it in the blob" answer already recorded -- rather than
// turning into a map-retry loop that ends only when the instruction budget runs
// out.
//
// Mapping and writing from inside the callback follows the same path the shims
// already take: the engine holds no lock across emu_start, so a shim writing
// guest memory from a code hook and this writing it from an unmapped hook are
// the same call.
func (r *Runtime) mapLazyPage(address uint64, size uint32, fetch bool) bool {
	page := address & ^uint64(4095)

	data, ok := r.lazyPages[page]
	if !ok {
		r.lazyAbsent++

		return false
	}

	delete(r.lazyPages, page)

	start := time.Now()

	if err := r.MemMap(page, 4096); err != nil {
		r.lazyFaults++

		return false
	}

	if err := r.MemWrite(page, data); err != nil {
		r.lazyFaults++

		return false
	}

	r.lazyFaults++
	r.lazyBytes += 4096
	r.lazyMs += time.Since(start).Milliseconds()

	return true
}

// lazyCensus reports what the indexed cache cost once it is being used: the
// page count and seconds the guest asked for, and the fraction of the index it
// did not need. Printed at the end of a run rather than at Close, which the
// store runtime reaches only when the app tears it down.
func (r *Runtime) lazyCensus() {
	if r.lazyPages == nil || r.lazyFaults+r.lazyAbsent == r.lazyPrinted {
		return
	}

	r.lazyPrinted = r.lazyFaults + r.lazyAbsent

	fmt.Fprintf(os.Stderr,
		"[SAP] lazy cache pages: %d mapped (%d KiB, %d ms), %d faults on addresses not in the blob, %d of %d still waiting\n",
		r.lazyFaults, r.lazyBytes/1024, r.lazyMs, r.lazyAbsent, len(r.lazyPages), r.lazyTotal)
}
