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
	// Purpose is why the request is being made: "licence" (the default) for a
	// package the account keeps, "metadata" for a field read out of the answer.
	Purpose string
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
	// What this request is addressed to. A second account failing where the first
	// works has to be one of these values, so they all go out -- the token as its
	// length only. This line is written into the log a person is asked to share
	// with a bug report, and a token's first eight characters are a fragment of a
	// live session credential that nothing here needs: the length already says
	// whether the field arrived empty, short, or the right size, which is every
	// question this line was ever used to answer.
	fmt.Fprintf(os.Stderr, "[SAP] ent input: dsid=%s storefront=%q token=%dch cookies=%d app=%d\n",
		input.DSID, input.StoreFront, len(input.Token),
		len(strings.Split(strings.TrimSpace(input.CookieHeader), ";")), input.AppID)

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

	// One runtime at a time. Two live sessions cannot share the engine: the
	// second open finds the first session's pages already mapped and patched,
	// skips restoring them, and hands the encoder objects belonging to a session
	// that has ended.
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

	// What the account switch costs is decided here, and the runtime is not the
	// thing that holds an account. Read what this request actually carries: the
	// body has the device `guid`, the per-DSID `kbsync` blob and the product ids;
	// the account object is created fresh and empty for every request by
	// `ephemeralAccount(nil)`; the encoder is told not to take cookies or
	// storefront from the guest (`setShouldSetCookieHeader: 0` in client.go); and
	// DSID, token, storefront and cookies are set per call from the caller's
	// headers. One runtime can therefore serve a second account, which is what the
	// switch now tests.
	//
	// The other route -- close and open a fresh session -- is closed off by two
	// device runs on two consecutive builds: the signature into
	// AppleMediaServices taken right after a `Close` returns -42306 with a null
	// output pointer, whether or not the close released the address space, and the
	// second session's encoder died at the same heap address every time on our own
	// `unknown receiver` panic. A close also puts the machine out of reach for the
	// signer that shares it, so a design that avoids closing is worth more here
	// than one that reopens cleanly.
	if runtime != nil && s.storeRuntimeDSID != 0 && s.storeRuntimeDSID != dsid {
		if !emulator.AccountReuse() {
			return EntDownloadResult{}, fmt.Errorf(
				"ent download: the store runtime was opened for DSID %d, not %d; "+
					"restart the app after switching accounts",
				s.storeRuntimeDSID, dsid)
		}

		fmt.Fprintf(os.Stderr, "[SAP] ent download: reusing DSID %d's store runtime for DSID %d\n",
			s.storeRuntimeDSID, dsid)
	}

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
		s.storeRuntimeDSID = dsid

		fmt.Fprintf(os.Stderr, "[SAP] ent download: store runtime opened\n")
	} else {
		// The blob belongs to the account, not to the session, and the slot holds
		// whichever account used it last: after a cross-account request the slot is
		// that other account's. Reading it here without asking which dsid it carries
		// is what sent A's request with B's blob on device and came back as
		// `ent/download (encoder) HTTP 500, 0 bytes` with an empty body -- and it is
		// the most likely author of the note that a second account is answered with a
		// framework error, since the slot has only ever held one blob.
		//
		// Resolution is memory or disk only. Generating runs the guest, and a store
		// session is mapped in it right now.
		var cached bool

		blob, cached = s.cachedKBSync(dsid)
		if !cached {
			return EntDownloadResult{}, fmt.Errorf(
				"ent download: no cached kbsync for DSID %d while its store session is open; "+
					"restart the app and download once with this account to generate one",
				dsid)
		}

		fromCache = true

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
		// The account's storefront is numeric ("143465-19,34"); the catalog lookup
		// wants a country code, and the number that names the country is the prefix.
		//
		// This loop used to try a hardcoded "tr" and then "us", so a Chinese account
		// asked the Turkish catalogue for a Chinese app and got an empty answer. The
		// full prefix table lives in the app; the ones that matter here are repeated,
		// with "us" kept as the last resort it always was.
		countries := []string{countryOf(input.StoreFront), "us"}

		for _, country := range countries {
			if country == "" {
				continue
			}

			if versionID = latestExternalVersionID(input.AppID, country); versionID != "" {
				break
			}
		}

		fmt.Fprintf(os.Stderr, "[SAP] ent download: externalVersionId looked up as %q (storefront %s)\n",
			versionID, input.StoreFront)
	}

	if versionID == "" {
		return EntDownloadResult{}, fmt.Errorf(
			"ent download: the store has no version of %d in storefront %q; "+
				"either the app is not sold there or the lookup failed",
			input.AppID, input.StoreFront)
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

	// The number this whole switch exists to produce: how much of the shared
	// cache one signed request actually needed.
	served, kiB, spent, absent, failed, waiting := runtime.LazyStats()

	fmt.Fprintf(os.Stderr, "[SAP] ent download: shared cache served %d pages (%d KiB in %d ms), %d faults outside the blob, %d failed, %d untouched\n",
		served, kiB, spent, absent, failed, waiting)

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
	if input.Purpose == "metadata" {
		// Nothing is stored for a metadata read. The answer carries the same fields
		// as a purchase, and storing them meant that browsing a 169-version list
		// wrote the sinf and metadata slots once per row -- with the sinfs of
		// versions nobody is downloading -- while the patch step reads those slots
		// as though they belonged to the package in hand. The counts still print
		// below, because they are evidence about the response, not a record of
		// what was kept.
		fmt.Fprintf(os.Stderr, "[SAP] ent download: metadata lookup, nothing stored\n")
	} else {
		if err := storeDownloadSinfs(text); err != nil {
			fmt.Fprintf(os.Stderr, "[SAP] ent download: could not store sinfs: %v\n", err)
		}

		if err := storeDownloadMetadata(text); err != nil {
			fmt.Fprintf(os.Stderr, "[SAP] ent download: could not store metadata: %v\n", err)
		}
	}

	fmt.Fprintf(os.Stderr, "[SAP] ent download: response carries sinfs=%d metadata=%d md5=%d\n",
		countOccurrences(text, "sinfs"),
		countOccurrences(text, "metadata"),
		countOccurrences(text, "md5"))

	// A refused blob is worth dropping. A licence or a session answer is not --
	// and the two arrive in the same field.
	//
	// The condition was "any failure while a cached blob was in play". Apple
	// answers 9610 (no licence), 5002 (already licensed), 2042/2034 (sign in
	// again) with a top-level failureType shaped exactly like a refused blob's,
	// so browsing the version history of an app the account does not own -- one
	// 9610 per row -- deleted that account's cached kbsync. The next real
	// download found no blob and, with a store session already open, was not
	// allowed to generate one: a dead end that only a restart clears, and the
	// restart costs the two minutes the cache exists to avoid.
	switch action := decideBlobAction(result.FailureType, fromCache); action {
	case actionDiscard:
		clearStoredKBSync(dsid)
		s.kbsyncBlob, s.kbsyncDSID = nil, 0

		fmt.Fprintf(os.Stderr, "[SAP] ent download: cached kbsync rejected (%s), discarded\n", result.FailureType)

	case actionKept:
		fmt.Fprintf(os.Stderr, "[SAP] ent download: cached kbsync kept (%s answers about the account, not the blob)\n",
			result.FailureType)

	case actionNothingStored:
		// An answer this list does not recognise, on a blob generated for this
		// very attempt. Nothing was stored, so there is nothing to drop, and the
		// code is printed rather than acted on: recording what a real refusal
		// looks like beats deleting a value on a guess.
		fmt.Fprintf(os.Stderr, "[SAP] ent download: failure (%s) on a freshly generated blob; nothing was stored\n",
			result.FailureType)

	case actionUnchanged:
	}

	// Only a blob Apple has accepted is worth keeping.
	if result.FailureType == "" && result.Status == 200 && !fromCache && len(blob) > 0 {
		storeKBSync(dsid, blob)
	}

	return result, nil
}

// SetLazyCachePages decides whether the store runtime maps the shared cache up
// front or hands it out a page at a time. It sits beside the open that reads it,
// because that call is where the consequence lands.
func SetLazyCachePages(on bool) { emulator.SetLazyCachePages(on) }

// SetAccountReuse decides whether a download for a second account may share the
// runtime that belongs to the first and open a new one. Off is the shipped
// behaviour: refuse, and ask for a restart.
func SetAccountReuse(on bool) { emulator.SetAccountReuse(on) }

// SetMappingCensus decides whether an open prints the mapping measurements --
// the map-cost census and the per-region mapped-per-page line. Off is the
// shipped behaviour: they are the loudest part of a normal launch, and the log
// they fill is the one a bug report gets typed into.
func SetMappingCensus(on bool) { emulator.SetMappingCensus(on) }

// blobAction is what a failed ent/download answer means for the cached kbsync.
type blobAction int

const (
	// actionUnchanged: the answer succeeded, so nothing is in question.
	actionUnchanged blobAction = iota

	// actionKept: a failure about the account or the licence. The value in the
	// request is not what Apple objected to, and deleting it would punish every
	// later download of an app that happens not to be licensed.
	actionKept

	// actionDiscard: an answer this code does not recognise, on a blob that came
	// from the cache. This is the self-heal path -- replaying a value the server
	// has refused never succeeds -- so unknown codes stay here rather than in
	// actionKept, and the line that prints them is how the list learns what a
	// real refusal looks like.
	actionDiscard

	// actionNothingStored: an unrecognised answer on a blob generated for this
	// attempt. It was never written to disk, so there is nothing to lose.
	actionNothingStored
)

// decideBlobAction separates "Apple refused this value" from "Apple refused
// this account".
//
// Every code in the kept list has been seen in a device log in this field: 9610
// and 5002 are licence answers, 2042, 2034 and 2002 are session answers, and the
// two names are what Apple writes instead of a number for the same trouble.
func decideBlobAction(failureType string, fromCache bool) blobAction {
	if failureType == "" {
		return actionUnchanged
	}

	switch failureType {
	case "9610", "5002", "2042", "2034", "2002", "signInRequired", "passwordTokenExpired":
		return actionKept
	}

	if fromCache {
		return actionDiscard
	}

	return actionNothingStored
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

// cachedKBSync answers with the blob this process or this device already holds
// for dsid, and with nothing otherwise. Generating is deliberately not part of
// it, because whether generating is *allowed* depends on the state of the
// machine, and the two callers here are on opposite sides of that question: the
// first download of a session generates, the reopen after a close must not.
func (s *Signer) cachedKBSync(dsid uint64) ([]byte, bool) {
	if s.kbsyncBlob != nil && s.kbsyncDSID == dsid {
		return s.kbsyncBlob, true
	}

	if stored := loadStoredKBSync(dsid); stored != nil {
		s.kbsyncBlob, s.kbsyncDSID = stored, dsid

		fmt.Fprintf(os.Stderr, "[SAP] ent download: kbsync from disk (%d bytes)\n", len(stored))

		return stored, true
	}

	return nil, false
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

// sinfSlotPath is where the last response's sinfs are kept.
//
// They are the FairPlay authorisation data: without them the package installs but
// the app cannot be decrypted at launch, which is why the patched copy needs them
// written into SC_Info before it is handed to an installer.
func sinfSlotPath() string {
	root, err := os.UserCacheDir()
	if err != nil {
		root = os.TempDir()
	}

	return filepath.Join(root, "dlipa", "last-sinfs.plist")
}

// SinfRecord is one entry of the response's sinfs array.
type SinfRecord struct {
	ID     int64  `plist:"id,omitempty"`
	Sinf   []byte `plist:"sinf,omitempty"`
	DPInfo []byte `plist:"dpInfo,omitempty"`
}

// storeDownloadSinfs writes songList[0].sinfs out as a binary plist.
func storeDownloadSinfs(body string) error {
	var document struct {
		SongList []struct {
			Sinfs []SinfRecord `plist:"sinfs"`
		} `plist:"songList"`
	}

	if _, err := plist.Unmarshal([]byte(body), &document); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	if len(document.SongList) == 0 || len(document.SongList[0].Sinfs) == 0 {
		return errors.New("response carries no sinfs")
	}

	encoded, err := plist.Marshal(document.SongList[0].Sinfs, plist.BinaryFormat)
	if err != nil {
		return fmt.Errorf("encode sinfs: %w", err)
	}

	path := sinfSlotPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create sinf directory: %w", err)
	}

	fmt.Fprintf(os.Stderr, "[SAP] ent download: stored %d sinf(s)\n", len(document.SongList[0].Sinfs))

	return os.WriteFile(path, encoded, 0o600)
}

// countryOf turns a storefront ("143465-19,34") into a country code.
//
// The number before the dash names the store; the table behind it is the inverse of
// upstream ipatool's map, so it covers every store that project knows. An unknown one
// returns empty and the caller falls back to the US catalogue, which is what the loop
// did for everything before.
func countryOf(storeFront string) string {
	front := strings.TrimSpace(storeFront)
	if front == "" {
		return ""
	}

	if dash := strings.IndexByte(front, '-'); dash > 0 {
		front = front[:dash]
	}

	return storefrontCountries[front]
}

// ClearCachedKBSync deletes the kbsync blobs kept for accounts.
//
// They are written by the binary that generated them and carry its assumptions. After
// an upgrade, the old blob is presented to a new engine and the guest rejects the
// request in setup -- "framework rejected response", with nothing about the cache in
// it. A fresh install never saw that failure, which is what pointed here.
func ClearCachedKBSync() error {
	path := kbsyncCachePath(0)

	dir := filepath.Dir(path)

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}

		return err
	}

	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "kbsync-") {
			continue
		}

		if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil {
			return err
		}
	}

	return nil
}
