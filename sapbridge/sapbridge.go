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
	"encoding/json"
	"errors"
	"fmt"
	"github.com/a23bc/dlipa-rebuild/sapbridge/internal/install"
	"github.com/a23bc/dlipa-rebuild/sapbridge/internal/measure"
	"github.com/a23bc/dlipa-rebuild/sapbridge/internal/sap/assetsremote"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/a23bc/dlipa-rebuild/sapbridge/internal/sap"
	"github.com/a23bc/dlipa-rebuild/sapbridge/internal/sap/machine"
	"github.com/a23bc/dlipa-rebuild/sapbridge/internal/storeauth"
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
//	sign-sap-setup       -> setupURL
//	sign-sap-setup-cert  -> certURL
//	sign-sap-version     -> version (200 today)
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
func (s *Signer) StoreSmoke(dsid string, token string, storefront string, entEndpoint string, cookieHeader string) (report string, err error) {
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
	// Read from disk, and resolve first if the app staged nothing: see
	// appleMediaServicesImage.
	image, err := appleMediaServicesImage()
	if err != nil {
		return "", err
	}

	smoker, ok := s.inner.(interface {
		StoreSmoke([]byte, sap.StoreAccount) (string, error)
	})
	if !ok {
		return "", fmt.Errorf("sapbridge: signer does not support the store smoke test")
	}

	return smoker.StoreSmoke(image, sap.StoreAccount{
		DSID:         dsid,
		Token:        token,
		StoreFront:   storefront,
		EntEndpoint:  entEndpoint,
		CookieHeader: cookieHeader,
	})
}

// EntDownload runs one ent/download request through the Store's own encoder and
// returns a JSON result. This is the production path: the probe proved it, and
// the Swift client no longer builds this request by hand.
//
// Purpose is "licence" or "metadata". Metadata asks no licence question and
// stores nothing: the response is read for a field, and writing the sinfs it
// carries would overwrite the slot the next real download patches from.
func (s *Signer) EntDownload(dsid string, token string, storefront string, endpoint string,
	cookieHeader string, appID int64, externalVersionID string,
	purpose string) (result string, err error) {
	if s == nil {
		return "", fmt.Errorf("sapbridge: signer is closed")
	}

	// Read from disk, and resolve first if the app staged nothing: see
	// appleMediaServicesImage. This is the call that used to fail on a build
	// without bundled assets.
	image, err := appleMediaServicesImage()
	if err != nil {
		return "", err
	}

	return s.inner.(interface {
		EntDownload([]byte, sap.EntDownloadInput) (string, error)
	}).EntDownload(image, sap.EntDownloadInput{
		DSID:              dsid,
		Token:             token,
		StoreFront:        storefront,
		Endpoint:          endpoint,
		CookieHeader:      cookieHeader,
		AppID:             appID,
		Purpose:           purpose,
		ExternalVersionID: externalVersionID,
	})
}

// Anisette provisions and proves a machine identity.
//
// It owns no SAP session: the runtimes it opens are its own and are closed
// before Headers returns. That is what lets Swift ask for identity headers
// before it has a signer, which is the order a sign-in needs.
type Anisette struct{}

// NewAnisette returns a handle for the identity calls.
func NewAnisette() *Anisette {
	return &Anisette{}
}

// ProvisionStore runs the Store provisioning step an SP answer asks for: it
// finishes the machine action with the challenge and a kbsync blob, then mints
// the Store AMD proof from the provisioned state.
func (a *Anisette) ProvisionStore(stateBase64, challenge, kbsync, identityJSON, hardwareHex string) (string, error) {
	state, err := base64.StdEncoding.DecodeString(stateBase64)
	if err != nil {
		return "", fmt.Errorf("sapbridge: provisioning state: %w", err)
	}

	hardware, err := hex.DecodeString(hardwareHex)
	if err != nil || len(hardware) != 6 {
		return "", fmt.Errorf("sapbridge: provisioning hardware identity")
	}

	var identity map[string]string
	if err := json.Unmarshal([]byte(identityJSON), &identity); err != nil {
		return "", fmt.Errorf("sapbridge: provisioning identity: %w", err)
	}

	headers := make(http.Header, len(identity))
	for name, value := range identity {
		headers.Set(name, value)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	provisioned, err := storeauth.ProvisionStoreAnisette(ctx, storeauth.NewHTTPClient(nil), state,
		challenge, "https://auth.itunes.apple.com/auth/v1/otp/1.5/finish",
		"Configurator/2.21 (Macintosh; OS X 27.0.1; 26A434) AppleWebKit/0625.2.5.11.6",
		kbsync, hardware, headers)
	if err != nil {
		return "", fmt.Errorf("sapbridge: provision store: %w", err)
	}

	// The provisioned state is what the store asked for; ask the generic
	// anisette path for the proof instead of opening the AMS type-2 guest a
	// second time. That second guest is what leaves the request runtime unable
	// to build a session.
	found, next, err := storeauth.AnisetteHeaders(ctx, storeauth.NewHTTPClient(nil), provisioned)
	if err != nil {
		return "", fmt.Errorf("sapbridge: proof after provisioning: %w", err)
	}

	proof := make(map[string]string, len(found))
	for name, values := range found {
		if len(values) != 0 {
			proof[name] = values[0]
		}
	}

	output := struct {
		Headers map[string]string `json:"headers"`
		State   string            `json:"state"`
	}{
		Headers: proof,
		State:   base64.StdEncoding.EncodeToString(next),
	}

	data, err := json.Marshal(output)
	if err != nil {
		return "", fmt.Errorf("sapbridge: provisioning result: %w", err)
	}

	return string(data), nil
}

// Headers takes the state from the previous call (base64, empty on first use)
// and returns JSON {"headers":{...},"state":"base64"}.
//
// The state is opaque and belongs in the app's keychain: handing back the
// state from before the call would provision a new machine instead of reusing
// the one the store already knows.
func (a *Anisette) Headers(stateBase64 string) (string, error) {
	var state []byte

	if stateBase64 != "" {
		decoded, err := base64.StdEncoding.DecodeString(stateBase64)
		if err != nil {
			return "", fmt.Errorf("sapbridge: anisette state: %w", err)
		}

		state = decoded
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	found, next, err := storeauth.AnisetteHeaders(ctx, storeauth.NewHTTPClient(nil), state)
	if err != nil {
		return "", fmt.Errorf("sapbridge: anisette headers: %w", err)
	}

	flat := make(map[string]string, len(found))
	for name, values := range found {
		if len(values) == 0 {
			continue
		}

		flat[name] = values[0]
	}

	output := struct {
		Headers map[string]string `json:"headers"`
		State   string            `json:"state"`
	}{
		Headers: flat,
		State:   base64.StdEncoding.EncodeToString(next),
	}

	data, err := json.Marshal(output)
	if err != nil {
		return "", fmt.Errorf("sapbridge: anisette result: %w", err)
	}

	return string(data), nil
}

// WarmStoreRuntime opens the Store runtime without sending a request.
func (s *Signer) WarmStoreRuntime() (result string, err error) {
	if s == nil {
		return "", fmt.Errorf("sapbridge: signer is closed")
	}

	image, err := appleMediaServicesImage()
	if err != nil {
		return "", err
	}

	warm, ok := s.inner.(interface {
		WarmStore(context.Context, []byte) error
	})
	if !ok {
		return "", fmt.Errorf("sapbridge: this build cannot warm the store runtime")
	}

	if err := warm.WarmStore(context.Background(), image); err != nil {
		return "", err
	}

	return "ok", nil
}

// AuthenticateOnce performs one authenticate exchange through the Store
// runtime and returns a JSON result. It never retries and never follows
// redirects: the Swift side owns both decisions.
//
// Input is JSON rather than a struct because gomobile maps exported method
// parameters, not Go structs: {"endpoint","appleId","password","guid",
// "cookie","userAgent","timeoutMs"}. Output is {"status","headers",
// "bodyBase64","url"}.
func (s *Signer) AuthenticateOnce(inputJSON string) (result string, err error) {
	if s == nil {
		return "", fmt.Errorf("sapbridge: signer is closed")
	}

	var input struct {
		Endpoint     string            `json:"endpoint"`
		AppleID      string            `json:"appleId"`
		Password     string            `json:"password"`
		GUID         string            `json:"guid"`
		Cookie       string            `json:"cookie"`
		UserAgent    string            `json:"userAgent"`
		ExtraHeaders map[string]string `json:"extraHeaders"`
		IdentityMode string            `json:"identityMode"`
		Bag          map[string]any    `json:"bag"`
		TimeoutMS    int               `json:"timeoutMs"`
	}

	if err := json.Unmarshal([]byte(inputJSON), &input); err != nil {
		return "", fmt.Errorf("sapbridge: authenticate input: %w", err)
	}

	timeout := time.Duration(input.TimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	if timeout > 2*time.Minute {
		timeout = 2 * time.Minute
	}

	image, err := appleMediaServicesImage()
	if err != nil {
		return "", err
	}

	exchange, ok := s.inner.(interface {
		AuthenticateOnce(context.Context, []byte, sap.AuthenticateInput) (sap.AuthenticateResult, error)
	})
	if !ok {
		return "", fmt.Errorf("sapbridge: this build does not support authenticate")
	}

	response, err := exchange.AuthenticateOnce(context.Background(), image, sap.AuthenticateInput{
		Endpoint:     input.Endpoint,
		AppleID:      input.AppleID,
		Password:     input.Password,
		GUID:         input.GUID,
		Cookie:       input.Cookie,
		UserAgent:    input.UserAgent,
		ExtraHeaders: input.ExtraHeaders,
		IdentityMode: input.IdentityMode,
		Bag:          input.Bag,
		Timeout:      timeout,
	})
	if err != nil {
		return "", err
	}

	output := struct {
		Status     int                 `json:"status"`
		Headers    map[string][]string `json:"headers"`
		BodyBase64 string              `json:"bodyBase64"`
		URL        string              `json:"url"`
	}{
		Status:     response.Status,
		Headers:    response.Headers,
		BodyBase64: base64.StdEncoding.EncodeToString(response.Body),
		URL:        response.URL,
	}

	data, err := json.Marshal(output)
	if err != nil {
		return "", fmt.Errorf("sapbridge: authenticate result: %w", err)
	}

	return string(data), nil
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
//	base64( 54 c8 b0 a9 88 ++ hardwareID[2:] )
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

// StartInstallServer serves a local package for itms-services and returns the URL
// to open. The caller keeps the returned server alive until the install ends.
func StartInstallServer(dataDir, packagePath, bundleID, version, title string) (url string, err error) {
	server, url, guide, startErr := install.Start(dataDir, install.Manifest{
		BundleID:    bundleID,
		Version:     version,
		Title:       title,
		PackagePath: packagePath,
	})
	if startErr != nil {
		return "", startErr
	}

	// Kept for the life of the process: the installer fetches the package while
	// the app is in the background, and a server that stops with the call would
	// turn every install into a timeout.
	installServersMu.Lock()
	installServers = append(installServers, server)
	lastGuide = guide
	installServersMu.Unlock()

	fmt.Fprintf(os.Stderr, "[SAP] install server ready\n")

	return url, nil
}

var (
	installServersMu sync.Mutex
	installServers   []*install.Server
	lastGuide        string
)

// InstallGuideURL is the page explaining how to trust the certificate, for the
// most recent server. The app opens it when the installer cannot connect, which
// happens until the profile is installed and trusted.
func InstallGuideURL() string {
	installServersMu.Lock()
	defer installServersMu.Unlock()

	return lastGuide
}

// BlankAudioPath drops the embedded silent track in the cache directory and
// returns where it landed. The keep-alive needs a URL, and Go is where the bytes
// are guaranteed to be: the resource phase did not pick the file up.
func BlankAudioPath(dataDir string) (path string, err error) {
	return install.BlankAudioPath(dataDir)
}

// FetchSapAssets runs the macOS restore-image extraction on this device and
// reports what it cost: transferred bytes, peak and cumulative heap, and time.
//
// It exists to answer one question with a measurement rather than an estimate:
// the same extraction takes about half a minute on a CI runner, and the only way
// to know what it costs on a phone is to run it there. Reporting only the elapsed
// time left the last device run answering "did it crash", which is not the
// question a memory ceiling asks.
func FetchSapAssets() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	cost := measure.Start()
	bundle, err := assetsremote.Load(ctx)
	if err != nil {
		// Report the spend even on failure: how far a phone got before it stopped
		// is the part that decides whether the approach fits at all.
		return "", fmt.Errorf("fetch sap assets: %w (%s)", err, cost.Finish())
	}

	total := len(bundle.AppleMediaServices) + len(bundle.Commerce) +
		len(bundle.ADID) + len(bundle.CoreFP) + len(bundle.CoreFPICXS) +
		len(bundle.FairPlayD) + len(bundle.FairPlayKext)

	return fmt.Sprintf("%s produced in %s",
		cost.Finish(), measure.Bytes(uint64(total))), nil
}

// ClearCachedKBSync drops the per-account kbsync blobs left by a previous build.
func ClearCachedKBSync() error {
	return sap.ClearCachedKBSync()
}

// EnableLazyCachePages chooses demand paging for the shared cache: open()
// indexes the 9,927 pages instead of mapping them, and the guest is handed one
// when it touches it.
//
// It is one-way and applies to the next open, because the two shapes are a bet
// on one unmeasured number -- the census prices mapping at about 0.8 s per MiB,
// so the eager path costs every launch 32.8 s, while demand paging costs about
// 4 ms per page actually touched. There is deliberately no bool parameter: the
// generated header in build/hdr shows gomobile rendering a bool *return* as
// BOOL and says nothing about a bool argument, and guessing wrong here costs a
// build-and-install cycle. The switch is read once by open(), which is why the
// app's row says next launch.
func EnableLazyCachePages() {
	sap.SetLazyCachePages(true)
}

// EnableAccountReuseProbe lets a download for a second account run through the
// store runtime the first account opened.
//
// Off is the shipped behaviour: the request is refused with a message that says
// to restart the app.
//
// On is a probe, not a feature. It rests on what the request actually carries:
// the per-account kbsync blob, an account object created fresh and empty for
// every request, and an encoder told not to take cookies or storefront from the
// guest -- so the runtime holds no account state to be wrong about. The claim
// that it does is what the refusal was written for, and it has never been
// reproduced with a log attached.
//
// What it does not do is close anything. Two device runs measured that route:
// the signature taken right after a Close returned -42306 both with and without
// releasing the address space, and the session opened afterwards died in our own
// bridge at the same heap address each time.
//
// One-way, like the cache switch, and there is no bool parameter for the reason
// given above: only bool returns are known to map to BOOL. The bridge reads the
// flag on every download, but the app only calls this at launch, so the row
// changes the next run rather than the one in hand -- and with no way to unset
// it, there is nothing to call mid-session anyway.
func EnableAccountReuseProbe() {
	sap.SetAccountReuse(true)
}

// EnableMappingCensus turns the mapping measurements back on: one line per used
// cell of the map-cost census, and one per region mapped page by page.
//
// Off is the shipped behaviour. These two are the loudest thing in a normal
// launch -- 89 of the 118 lines a store-runtime open writes inside its own
// second, device-measured, against 38 lines in that second with this switch off
// -- and they answer questions about the mapping itself rather than
// about the download, in the same log a bug report gets typed into.
//
// The instrument stays switchable rather than deleted because it is what killed
// three speculative levers and what found the coupling between the region phase
// and the shared cache. A measurement that can only be taken by editing the
// source is one that gets guessed at again.
//
// One-way, for the reason the two switches above give, and read once by open():
// the row changes the next launch rather than the one in hand.
func EnableMappingCensus() {
	sap.SetMappingCensus(true)
}
