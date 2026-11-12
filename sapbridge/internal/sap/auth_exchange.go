package sap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"howett.net/plist"

	"github.com/a23bc/dlipa-rebuild/sapbridge/internal/store/emulator"
	"github.com/a23bc/dlipa-rebuild/sapbridge/internal/store/profile"
)

// AuthenticateInput is one sign-in exchange. It carries no retry policy and no
// redirect state: the caller sends again, or does not.
type AuthenticateInput struct {
	Endpoint  string
	AppleID   string
	Password  string // the verification code is already appended by the caller
	GUID      string // 12 hex characters
	Cookie    string
	UserAgent string
	// ExtraHeaders carries the provisioned identity. The store names the pair
	// X-Apple-AMD / X-Apple-AMD-M; the anisette headers arrive as
	// X-Apple-I-MD / X-Apple-I-MD-M, so those two are renamed here rather than
	// at every caller.
	ExtraHeaders map[string]string
	// Bag is the urlBag dictionary. Apple's task reads routing and storefront
	// values from it; without it the request is built against an empty bag.
	Bag     map[string]any
	Timeout time.Duration
}

// AuthenticateResult is what the edge or the store answered, unread.
type AuthenticateResult struct {
	Status  int
	Headers map[string][]string
	Body    []byte
	URL     string
}

const (
	authenticatePath = "/WebObjects/MZFinance.woa/wa/authenticate"
	maxAuthBody      = 1 << 20
)

// AuthenticateOnce sends exactly one authenticate request through the Store
// runtime. Apple's AMSVerifyCredentialsTask builds the parameters; this
// function builds nothing but the envelope.
//
// No retry, no redirect: a 3xx is returned with its Location so the caller can
// decide, and a 204 is returned as a 204. That is a deliberate departure from
// upstream's three-try ladder -- the device captures showed the ladder only
// ages a fresh verification code.
func (s *Signer) AuthenticateOnce(ctx context.Context, image []byte, input AuthenticateInput) (AuthenticateResult, error) {
	if s == nil || s.machine == nil {
		return AuthenticateResult{}, errors.New("authenticate: no machine")
	}

	if len(image) < 4 {
		return AuthenticateResult{}, fmt.Errorf("authenticate: got %d bytes for AppleMediaServices", len(image))
	}

	endpoint, err := validateAuthenticateEndpoint(input.Endpoint)
	if err != nil {
		return AuthenticateResult{}, err
	}

	hardware, err := parseHardwareGUID(input.GUID)
	if err != nil {
		return AuthenticateResult{}, err
	}

	if strings.TrimSpace(input.AppleID) == "" {
		return AuthenticateResult{}, errors.New("authenticate: apple id is empty")
	}

	if input.Password == "" {
		return AuthenticateResult{}, errors.New("authenticate: password is empty")
	}

	if strings.ContainsAny(input.Cookie, "\r\n") {
		return AuthenticateResult{}, errors.New("authenticate: cookie contains a line break")
	}

	// The same lock the signer takes: a request must not land in the middle of
	// another signature.
	s.mu.Lock()
	defer s.mu.Unlock()

	engine := s.machine.Engine()
	if engine == nil {
		return AuthenticateResult{}, errors.New("authenticate: machine has no engine")
	}

	prepared, err := profile.Load(ctx)
	if err != nil {
		return AuthenticateResult{}, fmt.Errorf("authenticate: load profile: %w", err)
	}

	runtime := s.storeRuntime
	if runtime == nil {
		runtime, err = emulator.OpenWithEngineAt(ctx, engine, image, prepared, s.machine.HeapUsed())
		if err != nil {
			return AuthenticateResult{}, fmt.Errorf("authenticate: open runtime: %w", err)
		}

		s.storeRuntime = runtime
	}

	headers := make(http.Header)
	headers.Set("Content-Type", "application/x-apple-plist")
	headers.Set("User-Agent", input.UserAgent)

	if input.Cookie != "" {
		headers.Set("Cookie", input.Cookie)
	}

	for name, value := range input.ExtraHeaders {
		if value == "" || strings.ContainsAny(name, "\r\n") || strings.ContainsAny(value, "\r\n") {
			continue
		}

		// The authenticate request carries exactly two identity headers. The
		// rest of the anisette set (client time, locale, routing info, Mme)
		// belongs to other Apple endpoints; sending it here is what separated
		// this request from the reference, whose dump shows only these two.
		switch {
		case strings.EqualFold(name, "X-Apple-I-MD"):
			headers.Set("X-Apple-AMD", value)
		case strings.EqualFold(name, "X-Apple-I-MD-M"):
			headers.Set("X-Apple-AMD-M", value)
		}
	}

	timeout := input.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	// The reference client uses Go's default transport, which negotiates
	// HTTP/2. Forcing HTTP/1.1 here was inherited from the recording probe and
	// is the one transport-level difference left between the two requests.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ResponseHeaderTimeout = timeout
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	send := func(request *http.Request) (*http.Response, error) {
		if os.Getenv("DLIPA_DUMP_AUTH") == "1" && request.Body != nil {
			raw, readErr := io.ReadAll(request.Body)
			if readErr == nil {
				request.Body = io.NopCloser(bytes.NewReader(raw))

				var values map[string]any
				if _, decodeErr := plist.Unmarshal(raw, &values); decodeErr == nil {
					keys := make([]string, 0, len(values))
					for key := range values {
						keys = append(keys, key)
					}

					sort.Strings(keys)

					for _, key := range keys {
						switch key {
						case "appleId", "password":
							if text, ok := values[key].(string); ok {
								fmt.Fprintf(os.Stderr, "[AUTHD] body %s=string(%d)\n", key, len(text))
							}
						default:
							switch value := values[key].(type) {
							case string:
								fmt.Fprintf(os.Stderr, "[AUTHD] body %s=%q\n", key, value)
							case map[string]any:
								fmt.Fprintf(os.Stderr, "[AUTHD] body %s=dict(%d)\n", key, len(value))
							default:
								fmt.Fprintf(os.Stderr, "[AUTHD] body %s=%v\n", key, value)
							}
						}
					}
				}

				fmt.Fprintf(os.Stderr, "[AUTHD] body=%d hash=%x\n", len(raw), sha256.Sum256(raw))
			}
		}

		if os.Getenv("DLIPA_DUMP_AUTH") == "1" {
			fmt.Fprintf(os.Stderr, "[AUTHD] signature=%s\n", request.Header.Get("X-Apple-ActionSignature"))

			names := make([]string, 0, len(request.Header))
			for name := range request.Header {
				names = append(names, name)
			}

			sort.Strings(names)

			for _, name := range names {
				fmt.Fprintf(os.Stderr, "[AUTHD] final %s=%s\n", name, strings.Join(request.Header[name], ", "))
			}
		}

		// Keep Apple's Accept-Encoding exactly: the reference sends
		// "br, gzip, deflate" and the edge treats a narrower offer differently.
		return client.Do(request)
	}

	response, err := runtime.Execute(emulator.Request{
		URL:         endpoint,
		Method:      http.MethodPost,
		Operation:   "authenticate",
		NoRedirects: true,
		Headers:     headers,
		Parameters: map[string]any{
			"appleId":  input.AppleID,
			"attempt":  "1",
			"guid":     strings.ToLower(input.GUID),
			"password": input.Password,
			"rmp":      "0",
			"why":      "signIn",
		},
		Bag:        input.Bag,
		Sign:       s.signLocked,
		HardwareID: hardware,
		Timeout:    timeout,
		Transport:  send,
	})
	if err != nil {
		return AuthenticateResult{}, fmt.Errorf("authenticate: execute: %w", err)
	}
	defer func() { _ = response.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(response.Body, maxAuthBody+1))
	if err != nil {
		return AuthenticateResult{}, fmt.Errorf("authenticate: read body: %w", err)
	}

	if len(body) > maxAuthBody {
		return AuthenticateResult{}, fmt.Errorf("authenticate: response exceeds %d bytes", maxAuthBody)
	}

	result := AuthenticateResult{
		Status:  response.StatusCode,
		Headers: response.Header,
		Body:    body,
	}

	if response.Request != nil && response.Request.URL != nil {
		result.URL = response.Request.URL.String()
	}

	return result, nil
}

// WarmStore opens the Store runtime and leaves it open, so a caller can
// generate time-sensitive identity headers after the cold start instead of
// before it. No request is sent.
func (s *Signer) WarmStore(ctx context.Context, image []byte) error {
	if s == nil || s.machine == nil {
		return errors.New("warm store: no machine")
	}

	if len(image) < 4 {
		return fmt.Errorf("warm store: got %d bytes for AppleMediaServices", len(image))
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.storeRuntime != nil {
		return nil
	}

	engine := s.machine.Engine()
	if engine == nil {
		return errors.New("warm store: machine has no engine")
	}

	prepared, err := profile.Load(ctx)
	if err != nil {
		return fmt.Errorf("warm store: load profile: %w", err)
	}

	runtime, err := emulator.OpenWithEngineAt(ctx, engine, image, prepared, s.machine.HeapUsed())
	if err != nil {
		return fmt.Errorf("warm store: open runtime: %w", err)
	}

	s.storeRuntime = runtime

	return nil
}

// validateAuthenticateEndpoint keeps the Apple ID password on the one host and
// the one selector the login exchange is allowed to use. Redirect handling is
// the caller's job, and it uses the same rule.
func validateAuthenticateEndpoint(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", errors.New("authenticate: invalid endpoint")
	}

	if parsed.Scheme != "https" || parsed.User != nil || parsed.Fragment != "" {
		return "", fmt.Errorf("authenticate: refusing endpoint %q", parsed.Redacted())
	}

	if port := parsed.Port(); port != "" && port != "443" {
		return "", fmt.Errorf("authenticate: refusing endpoint with port %q", port)
	}

	host := strings.ToLower(parsed.Hostname())
	if host != "buy.itunes.apple.com" && !strings.HasSuffix(host, "-buy.itunes.apple.com") {
		return "", fmt.Errorf("authenticate: refusing host %q", host)
	}

	if strings.TrimRight(parsed.Path, "/") != authenticatePath {
		return "", fmt.Errorf("authenticate: refusing path %q", parsed.Path)
	}

	return parsed.String(), nil
}

func parseHardwareGUID(value string) ([]byte, error) {
	value = strings.TrimSpace(value)

	hardware, err := hex.DecodeString(value)
	if err != nil || len(hardware) != 6 {
		return nil, fmt.Errorf("authenticate: guid %q is not 6 bytes of hex", value)
	}

	return hardware, nil
}
