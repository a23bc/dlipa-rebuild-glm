// Package sapbridge exposes the Apple SAP signing stack to the DLiPA iOS app.
//
// It is a self-contained copy of the relevant parts of majd/ipatool v2
// (internal/sap/...), vendored because Go forbids importing another module's
// internal packages. The upstream code is MIT licensed.
package sapbridge

import (
        "context"
        "encoding/base64"
        "encoding/hex"
        "errors"
        "fmt"
        "os"
        "path/filepath"
        "strconv"
        "strings"
        "sync"
        "sync/atomic"
        "time"

        "github.com/a23bc/dlipa-rebuild/sapbridge/internal/sap"
	"github.com/a23bc/dlipa-rebuild/sapbridge/internal/sap/machine"
)

// Signer holds a live SAP session. One instance covers a whole app session:
// login -> purchase -> download. Create once, share, and Close on sign-out.
type Signer struct {
        // Every call here drives one guest machine in place, so they are
        // serialised. Without this, Sign (a download on a background queue) and
        // Close (a tab change on the main queue) read and write s.inner
        // concurrently: an interface is two words, and a torn read is a crash
        // with no report.
        mu        sync.Mutex
        inner     sap.ActionSigner
        hardware  []byte
        createdAt time.Time
}

// New runs the two-leg SAP handshake against Apple.
//
// setupURL / certURL / version come from the bag.xml response:
//
//      sign-sap-setup       -> setupURL
//      sign-sap-setup-cert  -> certURL
//      sign-sap-version     -> version (200 today)
//
// All panics inside the SAP stack (Unicorn, machimage, shims, etc.) are
// recovered here and converted to errors, so a bug deep in the guest
// runtime surfaces as a normal NSError on the Swift side instead of
// killing the host iOS process via os.Exit(2).
// liveSessions counts the sessions that currently own an emulator, and openMu
// makes the check-and-create atomic.
//
// iOS fits exactly one emulator. A second uc_open fails inside QEMU's
// code_gen_alloc, which calls exit(1): the app disappears with no crash report
// and the last thing in the log is whatever printed before. Two callers racing
// into this function produced exactly that, at a resident size far below what the
// first engine eventually uses, because the second one dies while the first is
// still being built.
//
// So a second attempt is refused with an error the caller can show, instead of
// being allowed to kill the process.
var (
        openMu       sync.Mutex
        liveSessions int32
)

func New(setupURL, certURL string, version int32, hardwareID []byte) (signer *Signer, err error) {
        openMu.Lock()
        defer openMu.Unlock()

        if live := atomic.LoadInt32(&liveSessions); live > 0 {
                return nil, fmt.Errorf("a SAP session is already open (%d); iOS fits only one emulator", live)
        }

        err = runRecovered("SAP handshake", func() error {
                var innerErr error
                signer, innerErr = newSigner(setupURL, certURL, version, hardwareID)
                return innerErr
        })
        if err != nil {
                return nil, err
        }

        atomic.AddInt32(&liveSessions, 1)

        return signer, err
}

// newSigner is the unwrapped handshake implementation. It panics on bugs;
// New() above recovers those panics.
func newSigner(setupURL, certURL string, version int32, hardwareID []byte) (*Signer, error) {
        if len(hardwareID) == 0 || len(hardwareID) > 20 {
                return nil, fmt.Errorf("hardware ID must be 1..20 bytes, got %d", len(hardwareID))
        }
        if version == 0 {
                return nil, errors.New("SAP version must be nonzero")
        }

        ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
        defer cancel()

        bundle, err := loadBundle()
        if err != nil {
                return nil, fmt.Errorf("SAP handshake: %w", err)
        }

        inner, err := sap.NewSigner(ctx, sap.Config{
                SetupURL:       setupURL,
                CertificateURL: certURL,
                Version:        uint32(version),
                HardwareID:     hardwareID,
        }, bundle)
        if err != nil {
                return nil, fmt.Errorf("SAP handshake: %w", err)
        }

        return &Signer{
                inner:     inner,
                hardware:  append([]byte(nil), hardwareID...),
                createdAt: time.Now(),
        }, nil
}

// Sign returns the raw signature bytes for body.
func (s *Signer) Sign(body []byte) (sig []byte, err error) {
        err = runRecovered("SAP sign", func() error {
                var innerErr error
                sig, innerErr = s.sign(body)
                return innerErr
        })
        return sig, err
}

func (s *Signer) sign(body []byte) ([]byte, error) {
        if s == nil {
                return nil, errors.New("signer is closed")
        }

        s.mu.Lock()
        defer s.mu.Unlock()

        if s.inner == nil {
                return nil, errors.New("signer is closed")
        }

        return s.inner.Sign(body)
}

// SignatureHeaderValue returns the ready-to-set value for the
// X-Apple-ActionSignature HTTP header.
func (s *Signer) SignatureHeaderValue(body []byte) (value string, err error) {
        err = runRecovered("SAP signature header", func() error {
                var innerErr error
                value, innerErr = s.signatureHeaderValue(body)
                return innerErr
        })
        return value, err
}

func (s *Signer) signatureHeaderValue(body []byte) (string, error) {
        sig, err := s.Sign(body)
        if err != nil {
                return "", err
        }
        return base64.StdEncoding.EncodeToString(sig), nil
}

// KBSync produces the FairPlay blob required by the bag's ent/download
// endpoint, on this signer's own machine.
//
// dsid must be the account's decimal Directory Services ID. The blob is stable
// per account and device, so callers should cache it: generating one runs the
// emulated Apple binaries and takes seconds.
func (s *Signer) GenerateKBSync(dsid string) (blob []byte, err error) {
        err = runRecovered("KBSync", func() error {
                var innerErr error
                blob, innerErr = s.kbsync(dsid)
                return innerErr
        })
        return blob, err
}

func (s *Signer) kbsync(dsid string) ([]byte, error) {
        if s == nil {
                return nil, errors.New("SAP signer is closed")
        }

        s.mu.Lock()
        defer s.mu.Unlock()

        if s.inner == nil {
                return nil, errors.New("SAP signer is closed")
        }

        numeric, err := parseDSID(dsid)
        if err != nil {
                return nil, err
        }

        ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
        defer cancel()

        fmt.Fprintf(os.Stderr, "[SAP] kbsync: running on the signer's machine...\n")
        sap.ReportRSS("before kbsync")

        blob, err := s.inner.KBSync(ctx, numeric)
        if err != nil {
                return nil, err
        }

        sap.ReportRSS("after kbsync")

        return blob, nil
}

// Hardware returns a copy of the device identity bytes.
// StoreSmoke opens the Store runtime on this signer's machine and reports how
// long each half took. It runs on the existing guest rather than creating one,
// because a second emulator cannot be allocated on this platform.
func (s *Signer) StoreSmoke(dsid string, token string, storefront string) (report string, err error) {
	if s == nil {
		return "", fmt.Errorf("sapbridge: signer is closed")
	}

	// Exclusive, not shared: the smoke opens a second tenant on the same engine
	// and patches call sites in memory the signer is still using.
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.inner == nil {
		return "", fmt.Errorf("sapbridge: signer is closed")
	}

	// inner is the ActionSigner interface; the smoke test lives on the concrete
	// signer, so ask for it rather than widening the interface for one caller.
	// Read the file the app staged rather than a cached Bundle. On device the
	// bundle handed to this call was empty even though the same loader, called
	// during pre-warm, had the real bytes -- so the file is the only source that
	// has been observed to be correct at both moments.
	imagePath := filepath.Join(BundleDirValue(), "AppleMediaServices")
	image, err := os.ReadFile(imagePath)
	if err != nil {
		return "", fmt.Errorf("sapbridge: read %s: %w", imagePath, err)
	}

	smoker, ok := s.inner.(interface {
		StoreSmoke([]byte, sap.StoreAccount) (string, error)
	})
	if !ok {
		return "", fmt.Errorf("sapbridge: signer does not support the store smoke test")
	}

	return smoker.StoreSmoke(image, sap.StoreAccount{
		DSID:       dsid,
		Token:      token,
		StoreFront: storefront,
	})
}

func (s *Signer) Hardware() []byte {
        if s == nil {
                return nil
        }
        return append([]byte(nil), s.hardware...)
}

// Close tears down the SAP session and releases the guest runtime.
func (s *Signer) Close() (err error) {
        err = runRecovered("SAP close", func() error {
                return s.close()
        })
        return err
}

func (s *Signer) close() error {
        if s == nil {
                return nil
        }

        s.mu.Lock()
        inner := s.inner
        s.inner = nil
        s.mu.Unlock()

        if inner == nil {
                return nil
        }

        // The counter is released by the deferred call rather than after
        // Close returns. A panic in Teardown skipped the decrement entirely,
        // liveSessions stayed at 1, and New refuses while it is non-zero -- so
        // one bad teardown made signing unreachable for the rest of the
        // process, with the only symptom being "a SAP session is already open".
        defer atomic.AddInt32(&liveSessions, -1)

        return inner.Close()
}

// KBSync produces the FairPlay blob required by the bag's ent/download
// endpoint. dsid must be the account's decimal Directory Services ID.
func KBSync(hardwareID []byte, dsid string) (blob []byte, err error) {
        err = runRecovered("KBSync", func() error {
                var innerErr error
                blob, innerErr = kbsync(hardwareID, dsid)
                return innerErr
        })
        return blob, err
}

// parseDSID converts the account DSID.
//
// It arrives as a string because gobind cannot map uint64 across the language
// boundary, and parsing it here keeps the Swift side free of numeric
// conversions.
func parseDSID(dsid string) (uint64, error) {
        numeric, err := strconv.ParseUint(strings.TrimSpace(dsid), 10, 64)
        if err != nil {
                return 0, fmt.Errorf("dsid must be a decimal number: %w", err)
        }
        if numeric == 0 {
                return 0, errors.New("dsid must be nonzero")
        }
        return numeric, nil
}

func kbsync(hardwareID []byte, dsid string) ([]byte, error) {
        numeric, err := parseDSID(dsid)
        if err != nil {
                return nil, err
        }

        ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
        defer cancel()

        // kbsync runs a second emulator alongside the one the signer already
        // holds, so it is the most memory-hungry thing the app does. Print the
        // trajectory: jetsam kills the process outright, and the only evidence
        // left behind is which line came last.
        fmt.Fprintf(os.Stderr, "[SAP] kbsync: resolving Apple binaries...\n")
        sap.ReportRSS("before kbsync bundle")

        bundle, err := loadBundle()
        if err != nil {
                return nil, fmt.Errorf("load Apple SAP assets: %w", err)
        }

        sap.ReportRSS("after kbsync bundle")
        fmt.Fprintf(os.Stderr, "[SAP] kbsync: opening store agent...\n")

        return machine.GenerateKBSync(ctx, bundle, hardwareID, numeric)
}

// SerialNumber returns ent/download's serialNumber field:
//
//      base64( 54 c8 b0 a9 88 ++ hardwareID[2:] )
//
// hardwareID must be exactly 6 bytes.
func SerialNumber(hardwareID []byte) (string, error) {
        if len(hardwareID) != 6 {
                return "", fmt.Errorf("serial number needs a 6-byte GUID, got %d", len(hardwareID))
        }
        prefix := []byte{0x54, 0xc8, 0xb0, 0xa9, 0x88}
        buf := make([]byte, 0, len(prefix)+len(hardwareID)-2)
        buf = append(buf, prefix...)
        buf = append(buf, hardwareID[2:]...)
        return base64.StdEncoding.EncodeToString(buf), nil
}

// GuidFromHardware returns the uppercase hex form used as the guid query
// parameter and plist field.
func GuidFromHardware(hardwareID []byte) string {
        return strings.ToUpper(hex.EncodeToString(hardwareID))
}

// ParseDSID parses the decimal DSID string the app stores.
func ParseDSID(value string) (int64, error) {
        // ParseUint returns uint64; gobind supports int64, so narrow deliberately.
        // A DSID is far below the int64 range, so this cannot overflow in practice.
        parsed, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
        if err != nil {
                return 0, err
        }
        return int64(parsed), nil
}
