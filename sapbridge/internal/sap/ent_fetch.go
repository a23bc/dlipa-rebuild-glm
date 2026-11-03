package sap

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
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

	blob, err := machine.GenerateKBSyncOn(ctx, s.machine, s.hardware, dsid)
	if err != nil {
		return EntDownloadResult{}, fmt.Errorf("ent download: kbsync: %w", err)
	}

	runtime, err := emulator.OpenWithEngineAt(ctx, engine, image, data, s.machine.HeapUsed())
	if err != nil {
		return EntDownloadResult{}, fmt.Errorf("ent download: open runtime: %w", err)
	}

	defer func() {
		if closeErr := runtime.Close(); closeErr != nil {
			fmt.Fprintf(os.Stderr, "[SAP] ent download: close: %v\n", closeErr)
		}
	}()

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

	address, err := runtime.EncodeProbe(endpoint, map[string]any{
		"creditDisplay":     "",
		"guid":              guid,
		"kbsync":            base64.StdEncoding.EncodeToString(blob),
		"salableAdamId":     strconv.FormatInt(input.AppID, 10),
		"serialNumber":      serial,
		"externalVersionId": input.ExternalVersionID,
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

	return result, nil
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
