package sap

import (
	"context"
	"errors"
	"fmt"
	"github.com/a23bc/dlipa-rebuild/sapbridge/internal/store/emulator"
	"net/http"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/a23bc/dlipa-rebuild/sapbridge/internal/sap/assets"
	"github.com/a23bc/dlipa-rebuild/sapbridge/internal/sap/machine"
)

type Signer struct {
	mu       sync.Mutex
	machine  *machine.Machine
	context  uint64
	hardware []byte
	closed   bool

	// Kept so the Store smoke test can reach AppleMediaServices without
	// re-reading the bundle from disk.
	bundle assets.Bundle

	// storeRuntime is the one Store runtime this process may have.
	//
	// Opening a second one does not work: the first open's pages are still
	// mapped and already patched, so the second open finds "everything already
	// there", skips restoring the profile's pages, and hands the encoder objects
	// that belong to the previous session. The guest then takes an exception --
	// observed as "unknown receiver ... for setAccount:" on the first call after
	// a second open. So it is opened once and reused until Close.
	storeRuntime *emulator.Runtime
	// The account the open runtime belongs to. Zero until one is opened.
	storeRuntimeDSID uint64

	// kbsyncBlob is the blob generated for kbsyncDSID. Generating one costs the
	// better part of a minute, and the same account keeps the same blob for the
	// life of the session.
	kbsyncBlob []byte
	kbsyncDSID uint64
}

// stepRecovered wraps one handshake step so a panic inside the guest
// runtime is logged to stderr (visible in iOS syslog) and re-thrown as
// an error. The top-level New() in package sapbridge installs its own
// recover() too, but this layer's recover gives us a per-step label so
// the device log can pinpoint exactly which step panicked.
func stepRecovered(step string, fn func() error) (err error) {
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		fmt.Fprintf(os.Stderr, "[SAP] PANIC in %s: %v\n", step, r)
		err = fmt.Errorf("SAP %s panicked: %v", step, r)
	}()
	return fn()
}

func NewSigner(ctx context.Context, config Config, bundle assets.Bundle) (ActionSigner, error) {
	if ctx == nil {
		return nil, errors.New("SAP signer context is nil")
	}

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("create SAP signer: %w", err)
	}

	if err := validateConfig(config); err != nil {
		return nil, err
	}

	fmt.Fprintf(os.Stderr, "[SAP] opening guest runtime...\n")
	reportRSS("before open runtime")

	var guest *machine.Machine
	if err := stepRecovered("open runtime", func() error {
		var openErr error
		guest, openErr = machine.Open(ctx, bundle)
		return openErr
	}); err != nil {
		return nil, fmt.Errorf("start Apple SAP runtime: %w", err)
	}

	// machine.Open has copied the Mach-O segments into Unicorn guest
	// memory and dropped its own references to bundle.CoreFP /
	// AppleMediaServices / Commerce. But this function's `bundle`
	// parameter (a value copy) still holds slice headers pointing at
	// the original ~118 MB of asset bytes. Clear them so the next GC
	// actually returns that memory to the OS before the SAP handshake
	// runs. CoreFPICXS is kept — the shims service still reads from it.
	bundle.CoreFP = nil
	bundle.AppleMediaServices = nil
	bundle.Commerce = nil
	runtime.GC()
	runtime.GC()

	reportRSS("after open runtime")

	signer := &Signer{
		machine:  guest,
		bundle:   bundle,
		hardware: append([]byte(nil), config.HardwareID...),
	}
	complete := false

	defer func() {
		if !complete {
			_ = signer.Close()
		}
	}()

	fmt.Fprintf(os.Stderr, "[SAP] initializing guest...\n")
	reportRSS("before initialize")
	if err := stepRecovered("initialize", func() error {
		var initErr error
		signer.context, initErr = guest.Initialize(signer.hardware)
		return initErr
	}); err != nil {
		reportRSS("after initialize (failed)")
		return nil, fmt.Errorf("initialize Apple SAP session: %w", err)
	}
	reportRSS("after initialize")

	protocol := setupProtocol{client: &http.Client{Timeout: 30 * time.Second}}

	fmt.Fprintf(os.Stderr, "[SAP] fetching certificate...\n")
	var certificate []byte
	if err := stepRecovered("fetch certificate", func() error {
		var certErr error
		certificate, certErr = protocol.certificate(ctx, config.CertificateURL)
		return certErr
	}); err != nil {
		return nil, err
	}

	fmt.Fprintf(os.Stderr, "[SAP] first exchange (creating setup message)...\n")
	var request []byte
	var state int32
	if err := stepRecovered("first exchange", func() error {
		var exErr error
		request, state, exErr = guest.Exchange(config.Version, signer.hardware, signer.context, certificate)
		return exErr
	}); err != nil {
		return nil, fmt.Errorf("create SAP setup message: %w", err)
	}

	if state != 1 {
		return nil, fmt.Errorf("SAP setup entered unexpected state %d", state)
	}

	if len(request) == 0 {
		return nil, errors.New("SAP setup message is empty")
	}

	fmt.Fprintf(os.Stderr, "[SAP] posting setup message to %s (%d bytes)...\n", config.SetupURL, len(request))
	reply, err := protocol.exchange(ctx, config.SetupURL, request)
	if err != nil {
		return nil, err
	}

	fmt.Fprintf(os.Stderr, "[SAP] got reply (%d bytes), second exchange...\n", len(reply))
	if err := stepRecovered("second exchange", func() error {
		var exErr error
		_, state, exErr = guest.Exchange(config.Version, signer.hardware, signer.context, reply)
		return exErr
	}); err != nil {
		return nil, fmt.Errorf("complete SAP setup: %w", err)
	}

	if state != 0 {
		return nil, fmt.Errorf("SAP setup completed in unexpected state %d", state)
	}

	fmt.Fprintf(os.Stderr, "[SAP] handshake complete!\n")
	complete = true

	return signer, nil
}

func (s *Signer) Sign(input []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.signLocked(input)
}

// signLocked is Sign without taking the lock, for callers that already hold it.
//
// StoreSmoke holds s.mu for its whole run -- it drives the same machine a
// signature would -- and signs inside it as a probe. Calling Sign from there
// deadlocked on the first probe: sync.Mutex is not reentrant, so the run simply
// stopped printing after the image line, with no error and no crash.
func (s *Signer) signLocked(input []byte) ([]byte, error) {
	if s.closed {
		return nil, errSignerClosed
	}

	signature, err := s.machine.Sign(s.context, input)
	if err != nil {
		return nil, fmt.Errorf("sign Apple request: %w", err)
	}

	if len(signature) == 0 {
		return nil, errors.New("sign Apple request: signature is empty")
	}

	return signature, nil
}

// KBSync produces the FairPlay blob required by ent/download.
//
// It runs on this signer's machine rather than opening another one. Two
// emulators cannot coexist in an iOS process: each costs about 173 MB resident,
// and the second uc_open dies inside QEMU's code_gen_alloc with exit(1), which
// leaves no crash report and no stderr line after the last one printed.
//
// The machine is the same one that signs, so the caller has to hold the lock
// across the call: the scratch area and the guest heap are shared state.
func (s *Signer) KBSync(ctx context.Context, dsid uint64) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, errSignerClosed
	}

	blob, err := machine.GenerateKBSyncOn(ctx, s.machine, s.hardware, dsid)
	if err != nil {
		return nil, err
	}

	if len(blob) == 0 {
		return nil, errors.New("kbsync: blob is empty")
	}

	return blob, nil
}

func (s *Signer) Close() error {
	if s == nil {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}

	s.closed = true

	var closeErrors []error

	// Before the machine: the Store runtime is a tenant on its engine and puts
	// the bytes it patched back when it closes. Tearing the machine down first
	// would leave that work with nothing to restore into.
	if s.storeRuntime != nil {
		closeErrors = append(closeErrors, s.storeRuntime.Close())
		s.storeRuntime = nil
	}

	if s.machine != nil && s.context != 0 {
		closeErrors = append(closeErrors, s.machine.Teardown(s.context))
		s.context = 0
	}

	// The engine is not closed.
	//
	// uc_close releases the engine, but QEMU's TCG state -- the translation
	// buffer above all -- is process-global and survives it. Every open/close
	// cycle therefore leaked a few megabytes: the diagnostics probe, opened and
	// closed fifteen times in a row, walked the process from 37 MB to 67 MB of
	// resident memory. That growth is what eventually made a later open fail in
	// code_gen_alloc with "Could not allocate dynamic translator buffer", which
	// QEMU turns into exit(1).
	//
	// Leaving the engine alone costs one engine's worth of memory for the life of
	// the process -- which is what the app had anyway, since a second engine
	// cannot exist -- and removes the leak entirely."
	if s.machine != nil {
		s.machine = nil
	}

	for index := range s.hardware {
		s.hardware[index] = 0
	}

	return errors.Join(closeErrors...)
}
