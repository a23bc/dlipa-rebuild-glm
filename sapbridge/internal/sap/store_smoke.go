package sap

// Store runtime smoke test.
//
// This answers one question and nothing else: can the Store runtime be built on
// this device, and how long does it take? Both numbers are measured rather than
// inferred, because the answer decides whether the emulator path is viable here.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/a23bc/dlipa-rebuild/sapbridge/internal/sap/machine"
	"io"
	"net/http"
	"net/url"
	"os"
	goruntime "runtime"
	"strconv"
	"strings"
	"time"

	"github.com/a23bc/dlipa-rebuild/sapbridge/internal/sap/unicorn"
	"github.com/a23bc/dlipa-rebuild/sapbridge/internal/store/emulator"
	"github.com/a23bc/dlipa-rebuild/sapbridge/internal/store/profile"
)

// StoreSmoke opens the Store runtime and reports how long each half took.
//
// It runs on a fresh guest rather than on the SAP machine's engine. The two want
// the same addresses: the machine has AppleMediaServices mapped around
// 0x1a0000000, and the profile's prepared pages live in that same range, so
// sharing one address space made the page mapping fail with UC_ERR_MAP. A second
// guest costs memory, but it removes the requirement that two independent
// layouts agree -- which is the point of this build.
// StoreAccount is the session the request is made on behalf of. Empty fields
// mean an anonymous request, which the Store answers with a 200 carrying an
// error plist rather than an HTTP failure.
type StoreAccount struct {
	DSID, Token, StoreFront string
}

func (s *Signer) StoreSmoke(image []byte, account StoreAccount) (_ string, returnedErr error) {
	// The result of this function goes to the app, not to stderr, and when it
	// fails early the log ends with nothing at all -- which reads exactly like a
	// crash. Printing the error here costs a line and removes that ambiguity.
	defer func() {
		if returnedErr != nil {
			fmt.Fprintf(os.Stderr, "[SAP] store smoke returned: %v\n", returnedErr)
		}
	}()

	if s == nil {
		return "", fmt.Errorf("store smoke: no machine")
	}

	// The smoke drives the same machine that signs and generates kbsync. The
	// lock the other entry points take is taken here too, so a diagnostic
	// cannot land in the middle of a download's signature.
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.machine == nil {
		return "", fmt.Errorf("store smoke: no machine")
	}

	if len(image) < 4 {
		return "", fmt.Errorf("store smoke: got %d bytes for AppleMediaServices", len(image))
	}

	// A background context, not s.context: that field is the SAP session value
	// (a uint64), not a Go context, and the name collision is easy to miss.
	ctx := context.Background()

	started := time.Now()

	data, err := profile.Load(ctx)
	if err != nil {
		return "", fmt.Errorf("store smoke: load profile: %w", err)
	}

	loaded := time.Since(started)

	imageSum := sha256.Sum256(image)

	magic := image
	if len(magic) > 8 {
		magic = magic[:8]
	}

	fmt.Fprintf(os.Stderr, "[SAP] store smoke: AMS %d bytes sha256 %x magic %x\n", len(image), imageSum, magic)

	opened := time.Now()

	// Share the SAP machine's engine. A second engine cannot be created in this
	// process at all: TCG's translator buffer is initialised once per process,
	// so the second uc_open fails with "Could not allocate dynamic translator
	// buffer". Sharing is not a memory optimisation here, it is the only option.
	engine := s.machine.Engine()
	if engine == nil {
		return "", fmt.Errorf("store smoke: machine has no engine")
	}

	// Enumerate every shared-cache page the guest reaches for and does not have,
	// in one run rather than one per build.
	collector := &missingPages{engine: engine, seen: map[uint64]bool{}, limit: 400}

	if collectHook, collectErr := engine.AddUnmappedHook(cacheRangeLow, cacheRangeHigh, collector.handle); collectErr == nil {
		defer func() {
			_ = collectHook.Close()
			fmt.Fprintf(os.Stderr, "[SAP] collect: %d pages listed\n", len(collector.pages))
		}()
	} else {
		fmt.Fprintf(os.Stderr, "[SAP] collect: not installed: %v\n", collectErr)
	}

	// Watches go on before the runtime opens: the store the question is about
	// happens while images are being loaded, and a watch installed afterwards
	// would miss it.
	watches, watchErr := s.watchGuestWrites(engine)
	if watchErr != nil {
		return "", fmt.Errorf("store smoke: %w", watchErr)
	}

	defer func() {
		for _, watch := range watches {
			_ = watch.Close()
		}
	}()

	// The machine keeps allocating on this heap whenever it signs, so the runtime
	// has to be told how much of it is already in use.
	// A/B against everything that follows: sign once before the Store runtime
	// exists. The handshake already signs and Apple accepted that signature, so
	// the machine can sign on its own. If this succeeds and the sign after the
	// runtime opens does not, the difference is the runtime, not the signer --
	// and the content does not matter to a function that signs bytes.
	probe := make([]byte, 354)
	for index := range probe {
		probe[index] = byte(index)
	}

	// signLocked, not Sign: this function already holds s.mu, which is not
	// reentrant.
	if signature, signErr := s.signLocked(probe); signErr != nil {
		fmt.Fprintf(os.Stderr, "[SAP] pre-open sign: %v\n", signErr)
	} else {
		fmt.Fprintf(os.Stderr, "[SAP] pre-open sign: %d bytes\n", len(signature))
	}

	// kbsync for E3 is generated here, before the store runtime opens. Once its
	// pages are in the shared guest, the SAP machine's generator runs into its
	// own one-minute bound: the run that tried it afterwards stopped at
	// 0x100000da692c and never came back.
	var entKBSync []byte

	if dsid, parseErr := strconv.ParseUint(account.DSID, 10, 64); parseErr == nil && dsid != 0 && len(s.hardware) == 6 {
		if blob, kerr := machine.GenerateKBSyncOn(ctx, s.machine, s.hardware, dsid); kerr != nil {
			fmt.Fprintf(os.Stderr, "[SAP] store smoke: build %s\n", buildStamp)

			fmt.Fprintf(os.Stderr, "[SAP] store smoke: kbsync for E3 failed: %v\n", kerr)
		} else {
			entKBSync = blob

			fmt.Fprintf(os.Stderr, "[SAP] store smoke: kbsync for E3: %d bytes\n", len(blob))
		}
	}

	runtime, err := emulator.OpenWithEngineAt(ctx, engine, image, data, s.machine.HeapUsed())
	if err != nil {
		return "", fmt.Errorf("store smoke: open runtime after %s: %w (image=%d bytes, plugin=%d bytes)",
			time.Since(opened).Round(time.Millisecond), err, len(image), len(data.Plugin))
	}

	openDuration := time.Since(opened)

	// Every return below has to close this, and the last measurement happens
	// here rather than at the end of the body.
	//
	// The runtime is a tenant on the signer's engine: it patches call sites and
	// installs a hook that survives Close unless Close is called. Close puts the
	// bytes back, and the only way to know it worked is to sign afterwards on
	// the engine the SAP machine gets back -- which is what this does, on every
	// return path. The encoder aborts on most runs, so a probe placed at the end
	// of the body never runs at all.
	defer func() {
		closeStarted := time.Now()
		closeErr := runtime.Close()
		closeDuration := time.Since(closeStarted)

		if closeErr != nil {
			fmt.Fprintf(os.Stderr, "[SAP] post-close: runtime close failed: %v\n", closeErr)
		}

		if signature, signErr := s.signLocked(probe); signErr != nil {
			fmt.Fprintf(os.Stderr, "[SAP] post-close sign: %v\n", signErr)
		} else {
			fmt.Fprintf(os.Stderr, "[SAP] post-close sign: %d bytes after a %s close\n",
				len(signature), closeDuration.Round(time.Millisecond))
		}
	}()

	// Third point in the same A/B: sign again immediately after open, before the
	// encoder touches anything. Opening reloads AppleMediaServices from the file,
	// and this machine initialised that image during the handshake -- if the
	// reload reset its data segments, signing breaks here and not at the
	// encoder's hand.
	// signLocked, not Sign: this function already holds s.mu, which is not
	// reentrant.
	if signature, signErr := s.signLocked(probe); signErr != nil {
		fmt.Fprintf(os.Stderr, "[SAP] post-open pre-encode sign: %v\n", signErr)
	} else {
		fmt.Fprintf(os.Stderr, "[SAP] post-open pre-encode sign: %d bytes\n", len(signature))
	}

	// Signing runs on the SAP machine but faulted code is reached through this
	// runtime's address space, so this runtime is the one that can say what a
	// fault was reading and whether that page was ever shipped. Cleared before
	// Close: the runtime is gone by then.
	s.machine.SetFaultExplainer(runtime.ExplainFault)

	entryProbes, entryErr := s.traceCalleeEntry()
	if entryErr != nil {
		return "", fmt.Errorf("store smoke: %w", entryErr)
	}

	for _, probe := range entryProbes {
		defer func() { _ = probe.Close() }()
	}

	callProbe, callProbeErr := s.traceProbeCall()
	if callProbeErr != nil {
		return "", fmt.Errorf("store smoke: %w", callProbeErr)
	}

	if callProbe != nil {
		defer func() { _ = callProbe.Close() }()
	}

	// Two message sends that cannot involve StoreKit state, to learn the calling
	// convention before attempting requestWithMethod:URL:parameters:. NSString
	// length is 5 for "hello"; isEqualToString: against "world" is false. If
	// those come back as 5 and 0, Invoke returns raw scalars and message dispatch
	// works -- which is the whole premise of the emulator.
	hello := runtime.New("NSString", "hello")

	length, err := runtime.Invoke(hello, "length")
	if err != nil {
		return "", fmt.Errorf("store smoke: invoke length: %w", err)
	}

	world := runtime.New("NSString", "world")

	equal, err := runtime.Invoke(hello, "isEqualToString:", world)
	if err != nil {
		return "", fmt.Errorf("store smoke: invoke isEqualToString: %w", err)
	}

	fmt.Fprintf(os.Stderr, "[SAP] store smoke: length=%d equal=%d\n", length, equal)

	// E1-b: drive the real StoreKit encoder far enough to know whether it will
	// produce a request at all. The helpers it needs live in the emulator package,
	// so the sequence is behind EncodeProbe rather than inlined here.
	// The payload is the one upstream sends for volumeStoreDownloadProduct
	// (ipatool appstore_download_product.go:268): creditDisplay, guid,
	// salableAdamId and serialNumber, with salableAdamId an integer because
	// upstream's App.ID is int64. Matching upstream was worth doing, but it did
	// not change the Store's answer and it was never going to: the run that
	// produced failureType 5002 was signed out, and an unauthorised request
	// fails however well formed it is. See the session line below.
	guid := strings.ToUpper(hex.EncodeToString(s.hardware))

	encodeStarted := time.Now()

	address, err := runtime.EncodeProbe(
		"https://p52-buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/volumeStoreDownloadProduct?guid="+guid,
		map[string]any{
			"creditDisplay": "",
			"guid":          guid,
			"salableAdamId": int64(389801252),
			"serialNumber":  "0",
		})
	if err != nil {
		return "", fmt.Errorf("store smoke: %w", err)
	}

	fmt.Fprintf(os.Stderr, "[SAP] store smoke: encoder produced request at %#x after %s\n",
		address, time.Since(encodeStarted).Round(time.Millisecond))

	// Inspection used to run here and cost 3m32s on the run that first got the
	// encoder working -- it walks the request object's lazy getters, and every
	// read is a message send into the guest. It is diagnostic only, so it now
	// runs after the transport attempt: the measurement that matters is whether
	// a response comes back, not whether the fields can be printed first.
	// E2, first step: hand the request the encoder built to the real transport
	// and see whether a response comes back. There is no session cookie here, so
	// the Store will refuse it; the status is the measurement, not a pass line.
	// What this proves is that the callback path -- guest request out, response
	// back in -- completes at all, which is what E2 is about.
	method, endpoint, body, _ := runtime.RequestParts(address)

	// Say which account the request is made on behalf of, in the log, every time.
	//
	// The previous run reported failureType 5002 and the question became whether
	// that was the payload or the session. It was neither answerable from the log
	// nor from the body: an anonymous request cannot be authorised to download,
	// so the failure plist is the expected answer and says nothing about the
	// request. Carrying the session state in the line removes that ambiguity for
	// good, instead of leaving it to be inferred from absent headers.
	session := "anonymous (no DSID, no token) -- a failure plist here is expected and is not evidence about the request"

	if account.DSID != "" {
		session = fmt.Sprintf("dsid=%s token=%d chars storefront=%q", account.DSID, len(account.Token), account.StoreFront)
	} else {
		fmt.Fprintln(os.Stderr, "[SAP] store smoke: no account; sign in before reading anything into the response")
	}

	fmt.Fprintf(os.Stderr, "[SAP] store smoke: session %s\n", session)

	client := &http.Client{Timeout: 30 * time.Second}

	// Execute turns these three into the account the guest signs for; the action
	// signature is the SAP header the Store checks. Without them the request is
	// anonymous and the Store answers 200 with a failure plist.
	headers := http.Header{}

	for key, value := range map[string]string{
		"X-Dsid":              account.DSID,
		"iCloud-DSID":         account.DSID,
		"X-Token":             account.Token,
		"X-Apple-Store-Front": account.StoreFront,
	} {
		if value != "" {
			headers.Set(key, value)
		}
	}

	attempt := func(sign func([]byte) ([]byte, error)) (*http.Response, error) {
		return runtime.Execute(emulator.Request{
			URL:        endpoint,
			Method:     method,
			Body:       body,
			Headers:    headers,
			HardwareID: s.hardware,
			Sign:       sign,
			Transport:  client.Do,
			Raw:        true,
		})
	}

	executed := ""

	// The sign call is where the guest started returning 0x200 from an indirect
	// call and storing it into a register that is later read as a pointer. The
	// trace says whether a host service answered that call, and which one.
	s.machine.TraceCalls(96)

	// And whether the interception fired at all: every call site that reaches a
	// recorded address prints its symbol name and arguments. 0x180675ce8 is
	// `malloc` in the profile, so this either shows `malloc(x0=0x200)` or shows
	// that the hook never ran there.
	runtime.TraceSymbols(64)

	// signLocked, not Sign: this function holds s.mu for its whole run. The two
	// probes were fixed for exactly this and this call was missed -- it only
	// deadlocks once the encoder gets far enough to sign the request, which is
	// downstream of where it currently stops, so the device run has not hit it
	// yet. Execute calls input.Sign when it signs the body.
	// The encoder got past the Swift metadata this round, and the run grew from
	// seconds to minutes: the screen stopped drawing and the watchdog killed the
	// process. A wall-clock budget turns "it hangs" into a line that says which
	// phase spent the time.
	const smokeBudget = 10 * time.Minute

	if spent := time.Since(started); spent > smokeBudget {
		fmt.Fprintf(os.Stderr, "[SAP] store smoke: %s spent before Execute, over the %s budget; skipping it\n",
			spent.Round(time.Second), smokeBudget)

		return "", fmt.Errorf("store smoke: budget of %s reached before Execute", smokeBudget)
	}

	executeStarted := time.Now()
	response, execErr := attempt(s.signLocked)

	fmt.Fprintf(os.Stderr, "[SAP] store smoke: Execute returned in %s\n",
		time.Since(executeStarted).Round(time.Millisecond))

	// The buffered calls are printed after the attempt, not during it: the one
	// that matters is the last one, and printing as they arrive let objc_retain
	// fill the quota long before the signer reached malloc.
	inspectStarted := time.Now()
	summary, inspectErr := runtime.InspectRequest(address)
	if inspectErr != nil {
		summary = "inspect failed: " + inspectErr.Error()
	}

	fmt.Fprintf(os.Stderr, "[SAP] store smoke: %s (inspected in %s)\n",
		summary, time.Since(inspectStarted).Round(time.Millisecond))

	runtime.DumpSymbolTrace()
	runtime.DumpTrace()

	// Emulation starts are counted because QEMU's thread budget is finite and the
	// run died in qemu_thread_create. A number in the thousands says the timer
	// thread per start was the cost; a small number says it was something else.
	fmt.Fprintf(os.Stderr, "[SAP] stats: emu_starts=%d goroutines=%d\n",
		unicorn.EmuStarts(), goruntime.NumGoroutine())

	// A bridge failure that happened while the SAP machine drove is stored here
	// and read by nobody: the machine reports only that the guest stopped.
	if bridgeErr := runtime.Fault(); bridgeErr != nil {
		fmt.Fprintf(os.Stderr, "[SAP] bridge: %v\n", bridgeErr)
	}

	if execErr != nil {
		executed = "signed: " + execErr.Error()

		// Signing runs the SAP machine, and for this request it reaches into
		// shared-cache code the blob does not carry: AMS picks the target out of
		// an obfuscated jump table, so no static scan of its data can see it.
		// That is a separate problem from whether the session is right, so ask
		// the Store again without a signature. Whatever comes back separates the
		// two: a 200 means account, headers and the callback path are all fine
		// and only the signature is missing.
		unsigned, unsignedErr := attempt(nil)

		if unsignedErr != nil {
			executed += " | unsigned: " + unsignedErr.Error()
		} else {
			payload, _ := io.ReadAll(io.LimitReader(unsigned.Body, 4096))
			_ = unsigned.Body.Close()

			executed += fmt.Sprintf(" | unsigned status=%d bytes=%d body=%s",
				unsigned.StatusCode, len(payload), hexHead(payload, 2048))
		}
	} else {
		payload, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		_ = response.Body.Close()

		executed = fmt.Sprintf("execute status=%d bytes=%d body=%s",
			response.StatusCode, len(payload), hexHead(payload, 2048))
	}

	fmt.Fprintf(os.Stderr, "[SAP] store smoke: %s\n", executed)

	// E3: the same encoder, aimed at ent/download.
	//
	// The classic endpoint answers 2042 for a session that has just signed in,
	// and every hand-built variation of that request answered the same thing.
	// The Store's own code is now able to send requests, so the next question is
	// whether its own request for this endpoint is served -- which is the E3
	// pass line: 200 with a songList in it.
	//
	// Three details differ from the classic call and all three come from
	// appstore_kbsync.go: the body carries kbsync, serialNumber is the hardware
	// serial in base64 rather than "0", and externalVersionId must be present.
	// The version id needs a catalog lookup this probe does not do yet, so it is
	// left empty and the answer will say whether that matters.
	entExecuted := "not attempted"

	// ent/download wants a concrete externalVersionId; upstream looks it up
	// first and only then sends the request. Leaving it empty produced 500 with
	// an empty body -- from the framework's own request, so the empty field is
	// the remaining difference rather than the request's shape.
	externalVersionID := latestExternalVersionID(389801252, "tr")

	fmt.Fprintf(os.Stderr, "[SAP] store smoke: externalVersionId %q\n", externalVersionID)

	switch {
	case len(entKBSync) == 0:
		entExecuted = "no kbsync (see the line above)"
	case len(s.hardware) != 6:
		entExecuted = "no hardware id"
	default:
		entExecuted = smokeEntDownload(runtime, s.hardware, guid, entKBSync, externalVersionID, headers, client)
	}

	fmt.Fprintf(os.Stderr, "[SAP] store smoke: ent %s\n", entExecuted)

	s.machine.SetFaultExplainer(nil)

	return fmt.Sprintf(
		"profile %d MB in %s; runtime opened in %s; length=%d equal=%d; session %s; request=%#x; %s",
		(len(data.Metadata)+len(data.Pages)+len(data.Plugin))/(1<<20),
		loaded.Round(time.Millisecond),
		openDuration.Round(time.Millisecond),
		length, equal, session, address, summary+" | "+executed,
	), nil
}

// guestProbeGlobal is temporary, and dies with the question it was added for.
//
// Signing stopped on `ldr x12, [x12]` where x12 came from this global in
// AppleMediaServices's bss, and the global held 0x200 instead of a pointer, so
// the next load read unmapped memory. Which store put 0x200 there is only
// visible at run time: the function that reaches it indexes an obfuscated
// dispatch table, and more than one path through it writes globals.
//
// The address is stable because the asset is pinned by hash in the build, and it
// is AppleMediaServices's `__DATA,__common`, not a cache page. Remove this, and
// the watch in watchGuestWrites, once the write site is known.
// cacheRangeLow and cacheRangeHigh bound the shared-cache address space the
// collector is interested in.
const (
	cacheRangeLow  = uint64(0x180000000)
	cacheRangeHigh = uint64(0x300000000)
)

const guestProbeGlobal = uint64(0x1e4d3bcc0)

// guestProbeCall is the indirect call whose result becomes 0x200, and
// guestProbeCallee is the stub it jumps to. Both temporary, like the global.
//
//	ldr   x8, [x23, w10, uxtw #3]   the callee, out of a dispatch table
//	mov   w0, #0x200                the argument
//	blraa x8, x17                   <- the call
//	str   x0, [x8]                  the result, stored into a VM register
//
// The callee reads as `ret` in the guest while the page blob has `mov x1, x0`
// there, so the call returns its argument and the register ends up holding one.
const (
	guestProbeCall       = uint64(0x1a24c3be4)
	guestProbeCallee     = uint64(0x180675ce8)
	guestProbeCalleeTail = uint64(0x1806b44f0)
)

// watchGuestWrites reports stores into the addresses under investigation.
//
// Two questions, one mechanism. The first is what put 0x200 into a VM register.
// The second is who rewrote the callee at 0x180675ce8: the page blob has
// `mov x1, x0` there, the guest reads `ret`, and that difference is why an
// indirect call returns its own argument. The rewrite happens while images load,
// so these go on before the runtime opens.
func (s *Signer) watchGuestWrites(engine *unicorn.Engine) ([]*unicorn.Hook, error) {
	if engine == nil {
		return nil, nil
	}

	var watches []*unicorn.Hook

	for _, probe := range []struct {
		name    string
		address uint64
	}{
		{"probe global", guestProbeGlobal},
		{"callee", guestProbeCallee},
		// The slot the encoder loads a function pointer from and calls. The
		// profile has a guest address there (0x180888cf0) and neither the
		// profile nor the cache blob contains the value the guest ends up
		// calling (0x7ff880000340), so something stores it at run time. This
		// watch names that store and its pc.
		{"bag slot", 0x1e800c958},
	} {
		seen := 0

		watch, err := engine.AddWriteWatch(probe.address, probe.address+8, func(address uint64, size uint32, value, pc uint64) {
			if seen >= 8 {
				return
			}

			seen++

			fmt.Fprintf(os.Stderr, "[SAP] watch: [%#x] <- %#x (%d bytes) from pc=%#x\n",
				address, value, size, pc)

			if seen == 8 {
				fmt.Fprintf(os.Stderr, "[SAP] watch: further writes to %s not reported\n", probe.name)
			}
		})
		if err != nil {
			// A watch that cannot be installed must not cost the run: the sign
			// attempt is the measurement, the probe is an extra.
			fmt.Fprintf(os.Stderr, "[SAP] watch: not installed on %s (%#x): %v\n", probe.name, probe.address, err)

			continue
		}

		watches = append(watches, watch)
	}

	return watches, nil
}

// missingPages collects the shared-cache pages the guest asks for and does not
// have, mapping a blank page so execution continues to the next one.
//
// Until now every run found exactly one page: the guest faulted on it, the page
// went into the blob, and the next run faulted on the next page. Mapping blank
// pages turns that into one run that enumerates them all. A blank page is not a
// substitute for the real one -- code read from it is garbage -- so the run that
// follows is expected to go wrong; the list is the product, not the result.
//
// Addresses the pinned cache does not have are harmless: the export skips them
// and says how many it skipped.
type missingPages struct {
	engine *unicorn.Engine
	seen   map[uint64]bool
	pages  []uint64
	limit  int
	capped bool
}

func (m *missingPages) handle(address uint64, size uint32, fetch bool) bool {
	page := address &^ 0xFFF

	// Below the shared cache this is a null dereference or a bad pointer, and
	// mapping it would hide the bug rather than report a missing page.
	if page < cacheRangeLow || page >= cacheRangeHigh {
		return false
	}

	if m.seen[page] {
		return true
	}

	if len(m.pages) >= m.limit {
		if !m.capped {
			m.capped = true
			fmt.Fprintf(os.Stderr, "[SAP] collect: stopping at %d pages\n", m.limit)
			_ = m.engine.Stop()
		}

		return false
	}

	m.seen[page] = true
	m.pages = append(m.pages, page)

	kind := "read"
	if fetch {
		kind = "fetch"
	}

	fmt.Fprintf(os.Stderr, "[SAP] collect: %#x (%s, %d bytes)\n", page, kind, size)

	if err := m.engine.MemMap(page, 4096); err != nil {
		return false
	}

	return true
}

// traceProbeCall reports the callee and argument of the call that produced
// 0x200, and whether its branch target is mapped at all.
func (s *Signer) traceProbeCall() (*unicorn.Hook, error) {
	engine := s.machine.Engine()
	if engine == nil {
		return nil, nil
	}

	seen := 0

	hook, err := engine.AddCodeHook(guestProbeCall, guestProbeCall, func(uint64, uint32) {
		if seen >= 8 {
			return
		}

		seen++

		callee, _ := engine.RegRead(unicorn.RegX8)
		argument, _ := engine.RegRead(unicorn.RegX0)

		fmt.Fprintf(os.Stderr, "[SAP] call site: blraa %#x(x0=%#x)\n", callee, argument)

		for _, address := range []uint64{callee, guestProbeCalleeTail} {
			word, readErr := engine.MemRead(address, 4)
			if readErr != nil {
				fmt.Fprintf(os.Stderr, "[SAP] call site: %#x unmapped: %v\n", address, readErr)

				continue
			}

			fmt.Fprintf(os.Stderr, "[SAP] call site: %#x readable, first word %x\n", address, word)
		}

		// The watch was installed before the runtime opened and still saw no
		// store, so these bytes were not written through uc_mem_write after that
		// point. Dumping the page says what the guest actually holds, and a
		// comparison against the same page in the blob says whether the whole
		// page was replaced or only this word.
		if page, readErr := engine.MemRead(guestProbeCallee&^0xFFF, 0x40); readErr == nil {
			fmt.Fprintf(os.Stderr, "[SAP] page head %#x: %x\n", guestProbeCallee&^0xFFF, page)
		}

		if around, readErr := engine.MemRead(guestProbeCallee-0x10, 0x30); readErr == nil {
			fmt.Fprintf(os.Stderr, "[SAP] page %#x: %x\n", guestProbeCallee-0x10, around)
		}
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "[SAP] watch: call site not hooked: %v\n", err)

		return nil, nil
	}

	return hook, nil
}

// traceCalleeEntry reports whether the guest ever executes at the callee address.
//
// The call site is recorded in the profile (13369 entries, `malloc` among them),
// the table reaches the runtime (13370 after the pinned one), and the call
// returns its own argument -- which is what a `ret` does when nothing
// intercepted it. So either the hook misses that address or the branch never
// lands there. One hook at the address itself tells which.
func (s *Signer) traceCalleeEntry() ([]*unicorn.Hook, error) {
	engine := s.machine.Engine()
	if engine == nil {
		return nil, nil
	}

	var hooks []*unicorn.Hook

	for _, probe := range []struct {
		name    string
		address uint64
	}{
		{"callee", guestProbeCallee},
		{"callee tail", guestProbeCalleeTail},
	} {
		seen := 0

		hook, err := engine.AddCodeHook(probe.address, probe.address, func(uint64, uint32) {
			if seen >= 4 {
				return
			}

			seen++

			x0, _ := engine.RegRead(unicorn.RegX0)
			pc, _ := engine.RegRead(unicorn.RegPC)

			fmt.Fprintf(os.Stderr, "[SAP] entered %s at %#x (x0=%#x)\n", probe.name, pc, x0)
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "[SAP] watch: %s not hooked: %v\n", probe.name, err)

			continue
		}

		hooks = append(hooks, hook)
	}

	return hooks, nil
}

// hexHead renders the first bytes of a response so a plist error body is
// readable in one log line: text when it is text, hex when it is not.
func hexHead(data []byte, limit int) string {
	if len(data) > limit {
		data = data[:limit]
	}

	for _, b := range data {
		if b == 0 || (b < 0x20 && b != '\n' && b != '\r' && b != '\t') {
			return hex.EncodeToString(data)
		}
	}

	return string(data)
}

// smokeEntDownload encodes and sends the ent/download request the way
// appstore_kbsync.go builds it, and reports what came back.
//
// Separate from the smoke's body because it is the E3 measurement: the pass line
// is a 200 whose plist carries a songList, and everything before that line is
// only worth reporting as context.
func smokeEntDownload(runtime *emulator.Runtime, hardware []byte, guid string, blob []byte, externalVersionID string, headers http.Header, client *http.Client) string {
	serial := base64.StdEncoding.EncodeToString(append([]byte{0x54, 0xc8, 0xb0, 0xa9, 0x88}, hardware[2:]...))

	endpoint := "https://downloaddispatch.itunes.apple.com/WebObjects/DownloadDispatch.woa/wa/ent/download?guid=" + guid

	kbsync := ""
	if len(blob) > 0 {
		kbsync = base64.StdEncoding.EncodeToString(blob)
	}

	address, err := runtime.EncodeProbe(endpoint, map[string]any{
		"creditDisplay": "",
		"guid":          guid,
		"kbsync":        kbsync,
		// String, not integer: sendEntDownloadRequest formats the id with
		// strconv.FormatInt. The classic path takes an integer, this one does
		// not, and sending the wrong one is a server-side 500 rather than a
		// readable failure.
		"salableAdamId":     strconv.FormatInt(389801252, 10),
		"serialNumber":      serial,
		"externalVersionId": externalVersionID,
	})
	if err != nil {
		return "encode failed: " + err.Error()
	}

	method, url, body, _ := runtime.RequestParts(address)

	// The encoder leaves the content type at application/x-apple-plist; upstream
	// overrides it to form-urlencoded for this endpoint, and that override is
	// part of the request the Store accepts. Redirects are off because X-Token
	// must not travel to wherever a redirect points.
	entHeaders := headers.Clone()
	entHeaders.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")

	response, execErr := runtime.Execute(emulator.Request{
		URL:         url,
		Method:      method,
		Body:        body,
		Headers:     entHeaders,
		HardwareID:  hardware,
		Transport:   client.Do,
		Raw:         true,
		NoRedirects: true,
	})
	if execErr != nil {
		return "execute failed: " + execErr.Error()
	}

	defer response.Body.Close()

	payload, _ := io.ReadAll(io.LimitReader(response.Body, 8192))
	text := string(payload)

	return fmt.Sprintf("status=%d bytes=%d songList=%v body=%s",
		response.StatusCode, len(payload), strings.Contains(text, "songList"), firstLine(text, 240))
}

// firstLine keeps log lines readable: plists arrive with newlines inside.
func firstLine(text string, limit int) string {
	text = strings.Join(strings.Fields(text), " ")
	if len(text) > limit {
		return text[:limit] + "…"
	}

	return text
}

// latestExternalVersionID asks the storefront catalog for the current version of
// an app, the way appstore_platform_version_lookup.go does.
//
// Plain HTTP, no session: this endpoint is the public one, and it is the step
// upstream performs before ent/download rather than something the Store does for
// us. The country code comes from the account's storefront in the real path; the
// probe is pinned to one storefront and says so.
func latestExternalVersionID(appID int64, countryCode string) string {
	endpoint := fmt.Sprintf(
		"https://uclient-api.itunes.apple.com/WebObjects/MZStorePlatform.woa/wa/lookup?version=2&id=%d&p=mdm-lockup&caller=MDM&platform=iphone&cc=%s&l=en",
		appID, strings.ToLower(countryCode))

	client := &http.Client{Timeout: 20 * time.Second}

	response, err := client.Get(endpoint)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[SAP] version lookup: %v\n", err)

		return ""
	}

	defer response.Body.Close()

	payload, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))

	var result struct {
		Results map[string]struct {
			Offers []struct {
				BuyParams string `json:"buyParams"`
				Version   struct {
					Display    string          `json:"display"`
					ExternalID json.RawMessage `json:"externalId"`
				} `json:"version"`
			} `json:"offers"`
		} `json:"results"`
	}

	if err = json.Unmarshal(payload, &result); err != nil {
		fmt.Fprintf(os.Stderr, "[SAP] version lookup: HTTP %d, %v\n", response.StatusCode, err)

		return ""
	}

	for _, item := range result.Results {
		for _, offer := range item.Offers {
			id := strings.Trim(string(offer.Version.ExternalID), "\"")

			if id != "" && id != "null" {
				return id
			}

			// Some storefronts only carry the version inside buyParams.
			if values, perr := url.ParseQuery(offer.BuyParams); perr == nil {
				if id := values.Get("appExtVrsId"); id != "" {
					return id
				}
			}
		}
	}

	fmt.Fprintf(os.Stderr, "[SAP] version lookup: HTTP %d, no externalId in the answer\n", response.StatusCode)

	return ""
}

// buildStamp identifies the binary that produced a log.
//
// Set with -ldflags at bind time. Without it a stderr log cannot be tied to a
// commit, and that has already cost a round: a run was read as evidence about a
// build that had not produced it.
var buildStamp = "unknown"
