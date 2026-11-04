package sap

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"howett.net/plist"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/a23bc/dlipa-rebuild/sapbridge/internal/sap/machine"
	"github.com/a23bc/dlipa-rebuild/sapbridge/internal/store/emulator"
	"github.com/a23bc/dlipa-rebuild/sapbridge/internal/store/profile"
)

// EntDownloadInput is one production ent/download request.
//
// The fields mirror what the Swift client already holds for a signed-in
// account plus the two things only the probe used to send: the bag's endpoint
// and the session cookie header.
type EntDownloadInput struct {
	DSID, Token, StoreFront string
	// Endpoint is the bag's volumeStoreDownloadProduct URL.
	Endpoint string
	// CookieHeader is the session the classic path replayed. downloaddispatch
	// answers 401 without it.
	CookieHeader string
	// AppID and ExternalVersionID identify the package.
	AppID             int64
	ExternalVersionID string
}

// EntDownloadResult is the answer, parsed only as far as the caller needs.
type EntDownloadResult struct {
	Status          int    `json:"status"`
	FailureType     string `json:"failureType,omitempty"`
	CustomerMessage string `json:"customerMessage,omitempty"`
	// URL is the first package URL in the response, empty when there is none.
	URL string `json:"url,omitempty"`
	// Body is the raw plist, so the Swift side can read whatever else it wants
	// without this layer having to model the whole schema.
	Body string `json:"body"`
}

// EntDownload runs one ent/download request through the Store's own encoder.
//
// This is the production half of E3: the same encoding, headers and execute path
// the probe proved, without the diagnostics. It opens a Store runtime, sends one
// request and closes it, because the runtime cannot stay open across calls yet --
// see the note on resident runtimes in the plan.
func (s *Signer) EntDownload(image []byte, input EntDownloadInput) (string, error) {
	result, err := s.entDownload(image, input)
	if err != nil {
		return "", err
	}

	payload, err := json.Marshal(result)
	if err != nil {
		return "", fmt.Errorf("ent download: encode result: %w", err)
	}

	return string(payload), nil
}

//nolint:cyclop // one linear request; splitting it would only move the sequence elsewhere
func (s *Signer) entDownload(image []byte, input EntDownloadInput) (EntDownloadResult, error) {
	if s == nil || s.machine == nil {
		return EntDownloadResult{}, fmt.Errorf("ent download: no machine")
	}

	// The same lock the signer takes: this runs on the machine that signs, and a
	// request must not land in the middle of another signature.
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(image) < 4 {
		return EntDownloadResult{}, fmt.Errorf("ent download: got %d bytes for AppleMediaServices", len(image))
	}

	engine := s.machine.Engine()
	if engine == nil {
		return EntDownloadResult{}, fmt.Errorf("ent download: machine has no engine")
	}

	ctx := context.Background()

	data, err := profile.Load(ctx)
	if err != nil {
		return EntDownloadResult{}, fmt.Errorf("ent download: load profile: %w", err)
	}

	// kbsync before the runtime opens: once the store's pages are in the guest
	// the generator runs past its bound. E3's first attempt died exactly there.
	dsid, err := strconv.ParseUint(input.DSID, 10, 64)
	if err != nil || dsid == 0 {
		return EntDownloadResult{}, fmt.Errorf("ent download: dsid %q is not numeric", input.DSID)
	}

	if len(s.hardware) != 6 {
		return EntDownloadResult{}, fmt.Errorf("ent download: no hardware id")
	}

	// One runtime per process, reopened never. A second open finds the first
	// session's pages already mapped and patched, skips restoring them, and the
	// encoder is handed objects from the previous session.
	runtime := s.storeRuntime

	var blob []byte

	// The blob is reused in this order: memory, disk, generate.
	//
	// Generation runs the engine and costs about a minute; Apple accepts the same
	// blob for the same (DSID, device) pair across launches, which is why ipatool
	// keeps one in the keychain. Disk is the same idea without the keychain: the
	// file lives under the app's cache directory and is only written after Apple
	// has accepted the blob once.
	fromCache := false

	if runtime == nil {
		if s.kbsyncBlob != nil && s.kbsyncDSID == dsid {
			blob, fromCache = s.kbsyncBlob, true
		} else if stored := loadStoredKBSync(dsid); stored != nil {
			blob, fromCache = stored, true
			s.kbsyncBlob, s.kbsyncDSID = stored, dsid

			fmt.Fprintf(os.Stderr, "[SAP] ent download: kbsync from disk (%d bytes)\n", len(stored))
		} else {
			blob, err = machine.GenerateKBSyncOn(ctx, s.machine, s.hardware, dsid)
			if err != nil {
				return EntDownloadResult{}, fmt.Errorf("ent download: kbsync: %w", err)
			}

			s.kbsyncBlob, s.kbsyncDSID = blob, dsid
		}

		runtime, err = emulator.OpenWithEngineAt(ctx, engine, image, data, s.machine.HeapUsed())
		if err != nil {
			return EntDownloadResult{}, fmt.Errorf("ent download: open runtime: %w", err)
		}

		s.storeRuntime = runtime

		fmt.Fprintf(os.Stderr, "[SAP] ent download: store runtime opened\n")
	} else {
		blob = s.kbsyncBlob

		fmt.Fprintf(os.Stderr, "[SAP] ent download: reusing the store runtime\n")
	}

	guid := fmt.Sprintf("%X", s.hardware)

	endpoint := input.Endpoint
	if endpoint == "" {
		endpoint = "https://downloaddispatch.itunes.apple.com/WebObjects/DownloadDispatch.woa/wa/ent/download"
	}

	if strings.Contains(endpoint, "?") {
		endpoint += "&guid=" + guid
	} else {
		endpoint += "?guid=" + guid
	}

	serial := base64.StdEncoding.EncodeToString(append([]byte{0x54, 0xc8, 0xb0, 0xa9, 0x88}, s.hardware[2:]...))

	// An empty externalVersionId is answered with 500 and no body -- the probe
	// never once succeeded without one, and the first real download reproduced
	// it. The caller does not always have a version (the UI passes nil for the
	// unpinned case), so it is looked up here the way the probe does.
	versionID := input.ExternalVersionID

	if versionID == "" {
		// The account's storefront is numeric ("143480-2,34"); the catalog
		// lookup wants a country code. Two tries cover both the account's
		// storefront and the default one, which is what the probe has been
		// doing with a hardcoded "tr".
		for _, country := range []string{"tr", "us"} {
			if versionID = latestExternalVersionID(input.AppID, country); versionID != "" {
				break
			}
		}

		fmt.Fprintf(os.Stderr, "[SAP] ent download: externalVersionId looked up as %q\n", versionID)
	}

	if versionID == "" {
		return EntDownloadResult{}, fmt.Errorf("ent download: no externalVersionId for %d", input.AppID)
	}

	address, err := runtime.EncodeProbe(endpoint, map[string]any{
		"creditDisplay":     "",
		"guid":              guid,
		"kbsync":            base64.StdEncoding.EncodeToString(blob),
		"salableAdamId":     strconv.FormatInt(input.AppID, 10),
		"serialNumber":      serial,
		"externalVersionId": versionID,
	})
	if err != nil {
		return EntDownloadResult{}, fmt.Errorf("ent download: encode: %w", err)
	}

	method, url, body, _ := runtime.RequestParts(address)

	headers := http.Header{}
	headers.Set("X-Dsid", input.DSID)
	headers.Set("iCloud-DSID", input.DSID)

	if input.Token != "" {
		headers.Set("X-Token", input.Token)
	}

	if input.StoreFront != "" {
		headers.Set("X-Apple-Store-Front", input.StoreFront)
	}

	// The three things E3 established, each one a build: form-urlencoded rather
	// than the encoder's plist content type, the Configurator agent because this
	// endpoint is a device-management one, and the session cookie because a token
	// alone is answered with 401.
	headers.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	headers.Set("User-Agent", "Configurator/2.18 (Macintosh; OS X 15.3.2; 24D81) AppleWebKit/0620.2.4.11.6")

	if input.CookieHeader != "" {
		headers.Set("Cookie", input.CookieHeader)
	}

	client := &http.Client{Timeout: 60 * time.Second}

	transport := func(request *http.Request) (*http.Response, error) {
		reply, doErr := client.Do(request)
		if doErr != nil {
			return nil, doErr
		}

		payload, readErr := io.ReadAll(io.LimitReader(reply.Body, 1<<20))
		_ = reply.Body.Close()

		reply.Body = io.NopCloser(bytes.NewReader(payload))

		if readErr != nil {
			return nil, readErr
		}

		return reply, nil
	}

	response, err := runtime.Execute(emulator.Request{
		URL:         url,
		Method:      method,
		Body:        body,
		Headers:     headers,
		HardwareID:  s.hardware,
		Transport:   transport,
		Raw:         true,
		NoRedirects: true,
	})
	if err != nil {
		return EntDownloadResult{}, fmt.Errorf("ent download: execute: %w", err)
	}

	defer response.Body.Close()

	payload, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return EntDownloadResult{}, fmt.Errorf("ent download: read body: %w", err)
	}

	text := string(payload)

	result := EntDownloadResult{
		Status:          response.StatusCode,
		Body:            text,
		FailureType:     plistString(text, "failureType"),
		CustomerMessage: plistString(text, "customerMessage"),
		URL:             firstPackageURL(text),
	}

	// Whether the response carries the pieces 4.6 needs. Step 2 rewrites
	// iTunesMetadata.plist, step 3 writes the sinfs into SC_Info; both are only
	// possible if this body contains them. Counted rather than parsed: a plist
	// decoder is the next step, and knowing the fields exist comes first.
	// The package Apple serves has no iTunesMetadata.plist; the store adds it from
	// the response's songList[0].metadata when it installs. Anything that installs
	// the package itself has to add it, so the dictionary is kept here where the
	// patch step can pick it up.
	if err := storeDownloadMetadata(text); err != nil {
		fmt.Fprintf(os.Stderr, "[SAP] ent download: could not store metadata: %v\n", err)
	}

	fmt.Fprintf(os.Stderr, "[SAP] ent download: response carries sinfs=%d metadata=%d md5=%d\n",
		countOccurrences(text, "sinfs"),
		countOccurrences(text, "metadata"),
		countOccurrences(text, "md5"))

	// Apple rejected the blob: drop it so the next attempt generates a fresh one
	// instead of replaying a value the server has already refused.
	if result.FailureType != "" && fromCache {
		clearStoredKBSync(dsid)
		s.kbsyncBlob, s.kbsyncDSID = nil, 0

		fmt.Fprintf(os.Stderr, "[SAP] ent download: cached kbsync rejected (%s), discarded\n", result.FailureType)
	}

	// Only a blob Apple has accepted is worth keeping.
	if result.FailureType == "" && result.Status == 200 && !fromCache && len(blob) > 0 {
		storeKBSync(dsid, blob)
	}

	return result, nil
}

// kbsyncCachePath is beside the staged assets: writable, already created by the
// staging step, and wiped with the app.
func kbsyncCachePath(dsid uint64) string {
	root, err := os.UserCacheDir()
	if err != nil {
		root = os.TempDir()
	}

	return filepath.Join(root, "dlipa", fmt.Sprintf("kbsync-%d.bin", dsid))
}

func loadStoredKBSync(dsid uint64) []byte {
	data, err := os.ReadFile(kbsyncCachePath(dsid))
	if err != nil || len(data) == 0 {
		return nil
	}

	return data
}

func storeKBSync(dsid uint64, blob []byte) {
	path := kbsyncCachePath(dsid)
	_ = os.MkdirAll(filepath.Dir(path), 0o700)

	if err := os.WriteFile(path, blob, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "[SAP] ent download: could not store kbsync: %v\n", err)
	}
}

func clearStoredKBSync(dsid uint64) {
	_ = os.Remove(kbsyncCachePath(dsid))
}

// plistString pulls a top-level <key>name</key><string>value</string> pair.
func plistString(text, key string) string {
	marker := "<key>" + key + "</key>"

	index := strings.Index(text, marker)
	if index < 0 {
		return ""
	}

	rest := text[index+len(marker):]

	start := strings.Index(rest, "<string>")
	if start < 0 {
		return ""
	}

	rest = rest[start+len("<string>"):]

	end := strings.Index(rest, "</string>")
	if end < 0 {
		return ""
	}

	return strings.TrimSpace(rest[:end])
}

// firstPackageURL finds the first <key>URL</key> entry, which is the package.
func firstPackageURL(text string) string {
	const marker = "<key>URL</key>"

	index := strings.Index(text, marker)
	if index < 0 {
		return ""
	}

	rest := text[index+len(marker):]

	start := strings.Index(rest, "<string>")
	if start < 0 {
		return ""
	}

	rest = rest[start+len("<string>"):]

	end := strings.Index(rest, "</string>")
	if end < 0 {
		return ""
	}

	value := strings.TrimSpace(rest[:end])
	if !strings.HasPrefix(value, "http") {
		return ""
	}

	return value
}

// countOccurrences counts a substring in the response body.
func countOccurrences(body, needle string) int {
	return strings.Count(body, needle)
}

// metadataSlotPath is where the last response's metadata dictionary is kept.
//
// One slot, overwritten per download: the patch runs seconds after the download it
// belongs to, and a per-item key would need the item identity plumbed through both
// languages for no gain yet.
func metadataSlotPath() string {
	root, err := os.UserCacheDir()
	if err != nil {
		root = os.TempDir()
	}

	return filepath.Join(root, "dlipa", "last-metadata.plist")
}

// storeDownloadMetadata writes songList[0].metadata out as a binary plist.
func storeDownloadMetadata(body string) error {
	var document struct {
		SongList []struct {
			Metadata map[string]any `plist:"metadata"`
		} `plist:"songList"`
	}

	if _, err := plist.Unmarshal([]byte(body), &document); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	if len(document.SongList) == 0 || len(document.SongList[0].Metadata) == 0 {
		return errors.New("response carries no songList metadata")
	}

	encoded, err := plist.Marshal(document.SongList[0].Metadata, plist.BinaryFormat)
	if err != nil {
		return fmt.Errorf("encode metadata: %w", err)
	}

	path := metadataSlotPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create metadata directory: %w", err)
	}

	return os.WriteFile(path, encoded, 0o600)
}
