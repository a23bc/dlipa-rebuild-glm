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

	watch, watchErr := s.watchGuestWrites()
	if watchErr != nil {
		return "", fmt.Errorf("store smoke: %w", watchErr)
	}

	if watch != nil {
		defer func() { _ = watch.Close() }()
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
const guestProbeGlobal = uint64(0x1e4d3bcc0)

// watchGuestWrites reports stores into the probe global, with the pc that made
// them. Capped, because a watch inside a loop would otherwise fill the log with
// the same site repeated.
func (s *Signer) watchGuestWrites() (*unicorn.Hook, error) {
	engine := s.machine.Engine()
	if engine == nil {
		return nil, nil
	}

	seen := 0

	watch, err := engine.AddWriteWatch(guestProbeGlobal, guestProbeGlobal+8, func(address uint64, size uint32, value, pc uint64) {
		if seen >= 8 {
			return
		}

		seen++

		fmt.Fprintf(os.Stderr, "[SAP] watch: [%#x] = %#x (%d bytes) from pc=%#x\n",
			address, value, size, pc)

		if seen == 8 {
			fmt.Fprintln(os.Stderr, "[SAP] watch: further writes to the probe global not reported")
		}
	})
	if err != nil {
		// A watch that cannot be installed must not cost the run: the sign
		// attempt is the measurement, the probe is an extra.
		fmt.Fprintf(os.Stderr, "[SAP] watch: not installed on %#x: %v\n", guestProbeGlobal, err)

		return nil, nil
	}

	return watch, nil
}

// guestProbeCall is the indirect call whose result becomes 0x200. Temporary,
// like guestProbeGlobal, and removed with it.
//
//	  ldr   x8, [x23, w10, uxtw #3]   the callee, out of a dispatch table
//	  mov   w0, #0x200                the argument
//	  mov   x17, #0xbc0b
//	  blraa x8, x17                   <- watched
//	  str   x0, [x8]                  the result, stored into a VM register
const guestProbeCall = uint64(0x1a24c3be4)

// traceProbeCall reports the callee and argument of that one call.
//
// Nothing a host service did produced 0x200 -- the call trace came back empty,
// so the guest never asked the host for anything during the sign attempt. That
// leaves the callee: one instruction is enough to hook, and the address it jumps
// to is what the next disassembly should look at.
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
