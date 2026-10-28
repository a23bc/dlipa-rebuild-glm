package sap

// Store runtime smoke test.
//
// This answers one question and nothing else: can the Store runtime be built on
// this device, and how long does it take? Both numbers are measured rather than
// inferred, because the answer decides whether the emulator path is viable here.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
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

func (s *Signer) StoreSmoke(image []byte, account StoreAccount) (string, error) {
	if s == nil || s.machine == nil {
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
	runtime, err := emulator.OpenWithEngineAt(ctx, engine, image, data, s.machine.HeapUsed())
	if err != nil {
		return "", fmt.Errorf("store smoke: open runtime after %s: %w (image=%d bytes, plugin=%d bytes)",
			time.Since(opened).Round(time.Millisecond), err, len(image), len(data.Plugin))
	}

	openDuration := time.Since(opened)

	// Signing runs on the SAP machine but faulted code is reached through this
	// runtime's address space, so this runtime is the one that can say what a
	// fault was reading and whether that page was ever shipped. Cleared before
	// Close: the runtime is gone by then.
	s.machine.SetFaultExplainer(runtime.ExplainFault)

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

	fmt.Fprintf(os.Stderr, "[SAP] store smoke: encoder produced request at %#x\n", address)

	// E1-c: the request object exists; this says whether it is usable. A URL, a
	// method and a body of the right shape are what Execute needs before wiring
	// it is worth doing.
	summary, inspectErr := runtime.InspectRequest(address)
	if inspectErr != nil {
		summary = "inspect failed: " + inspectErr.Error()
	}

	fmt.Fprintf(os.Stderr, "[SAP] store smoke: %s\n", summary)

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

	response, execErr := attempt(s.Sign)

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

	closeStart := time.Now()

	s.machine.SetFaultExplainer(nil)

	if err := runtime.Close(); err != nil {
		return "", fmt.Errorf("store smoke: close runtime: %w", err)
	}

	closed := time.Since(closeStart)

	return fmt.Sprintf(
		"profile %d MB in %s; runtime opened in %s; closed in %s; length=%d equal=%d; session %s; request=%#x; %s",
		(len(data.Metadata)+len(data.Pages)+len(data.Plugin))/(1<<20),
		loaded.Round(time.Millisecond),
		openDuration.Round(time.Millisecond),
		closed.Round(time.Millisecond),
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
//	  ldr   x8, [x23, w10, uxtw #3]   the callee, out of a dispatch table
//	  mov   w0, #0x200                the argument
//	  blraa x8, x17                   <- the call
//	  str   x0, [x8]                  the result, stored into a VM register
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
