package emulator

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strings"
)

// EncodeProbe drives the real StoreKit request encoder far enough to know whether
// it will produce a request at all.
//
// It exists because the helpers it needs -- ephemeralAccount, frozenBagFromValues,
// importValue, resolveAddress -- are unexported, so a caller outside this package
// cannot assemble the same sequence. Each step is reported separately: a failure
// names the call it died in rather than just "encoding failed".
//
// This is a diagnostic entry point for the E1-b milestone. It is not used by the
// production request path, which goes through Execute.
func (r *Runtime) EncodeProbe(endpoint string, parameters map[string]any) (uint64, error) {
	// nil, not an empty map: ephemeralAccount returns a fresh account straight
	// away for nil, but treats a map as a saved account and parses its DSID.
	// An empty map therefore fails with "invalid saved account identifier".
	//
	// The probe is the page holding ___swift_mutable_project_boxed_
	// opaque_existential_1, where initWithBag stopped on device. Reading it here
	// says whether AMS code was mapped *before* the encoder was built, which
	// separates "we never mapped it" from "something unmapped it afterwards".
	// The address that faulted is no longer guessed from this: fault.go decodes
	// the instruction at the PC.
	const swiftHelper = 0x1a2a061f8

	if probe, readErr := r.engine.MemRead(swiftHelper, 4); readErr != nil {
		fmt.Fprintf(os.Stderr, "[SAP] probe: %#x UNREADABLE: %v\n", swiftHelper, readErr)
	} else {
		fmt.Fprintf(os.Stderr, "[SAP] probe: %#x readable %x\n", swiftHelper, probe)
	}

	account, err := r.ephemeralAccount(nil)
	if err != nil {
		return 0, fmt.Errorf("ephemeral account: %w", err)
	}

	bag, err := r.frozenBagFromValues(map[string]any{})
	if err != nil {
		return 0, fmt.Errorf("frozen bag: %w", err)
	}

	encoder, err := r.Invoke(r.New("AMSURLRequestEncoder", nil), "initWithBag:", bag)
	if err != nil {
		r.dumpFaultState()
		return 0, fmt.Errorf("encoder initWithBag: %w", err)
	}

	if _, err = r.Invoke(encoder, "setAccount:", account); err != nil {
		r.dumpFaultState()
		return 0, fmt.Errorf("encoder setAccount: %w", err)
	}

	promise, err := r.Invoke(encoder, "requestWithMethod:URL:parameters:",
		4, r.New("NSURL", endpoint), r.importValue(parameters))
	if err != nil {
		r.dumpFaultState()
		return 0, fmt.Errorf("requestWithMethod:URL:parameters:: %w", err)
	}

	address, err := r.resolveAddress(promise)
	if err != nil {
		r.dumpFaultState()
		return 0, fmt.Errorf("resolve promise: %w", err)
	}

	return address, nil
}

// dumpFaultState lives in fault.go: it decodes the instruction at the PC
// instead of guessing which address was missing.


// InspectRequest reads back what the encoder produced.
//
// E1-b stopped at "there is a request object". Whether that object is usable --
// a URL, a method, a body with the expected shape -- is a separate question, and
// the answer decides whether wiring Execute is worth doing next.
func (r *Runtime) InspectRequest(request uint64) (string, error) {
	method, address, body, names := r.RequestParts(request)

	bodyText := printable(body, 1024)

	// The plan's E1 pass line is that the body carries the keys upstream sends.
	// Naming which ones arrived turns "looks like a plist" into a verdict.
	var present []string

	for _, key := range []string{"salableAdamId", "creditDisplay"} {
		if strings.Contains(bodyText, key) {
			present = append(present, key)
		}
	}

	return fmt.Sprintf("method=%s url=%s body=%d headers=[%s] keys=[%s] body=%s",
		method, address, len(body), strings.Join(names, ","),
		strings.Join(present, ","), bodyText), nil
}

// RequestParts reads the method, URL, body and header names back out of the
// request the encoder built, so the same bytes can be handed to the transport.
func (r *Runtime) RequestParts(request uint64) (method, endpoint string, body []byte, headers []string) {
	if value, err := r.Invoke(request, "HTTPMethod"); err == nil && value != 0 {
		method, _ = r.guestString(value)
	}

	if value, err := r.Invoke(request, "URL"); err == nil && value != 0 {
		if absolute, err := r.Invoke(value, "absoluteString"); err == nil && absolute != 0 {
			endpoint, _ = r.guestString(absolute)
		}
	}

	if value, err := r.Invoke(request, "HTTPBody"); err == nil && value != 0 {
		body, _ = r.guestData(value)
	}

	return method, endpoint, body, r.headerNames(request)
}

// headerNames lists the header fields the request carries. The count alone says
// nothing about whether the encoder set the ones Apple reads.
func (r *Runtime) headerNames(request uint64) []string {
	fields, err := r.Invoke(request, "allHTTPHeaderFields")
	if err != nil || fields == 0 {
		return nil
	}

	keys, err := r.Invoke(fields, "allKeys")
	if err != nil || keys == 0 {
		return nil
	}

	count, err := r.Invoke(keys, "count")
	if err != nil {
		return nil
	}

	names := make([]string, 0, count)

	for index := uint64(0); index < count && index < 64; index++ {
		key, err := r.Invoke(keys, "objectAtIndex:", index)
		if err != nil || key == 0 {
			continue
		}

		if name, err := r.guestString(key); err == nil && name != "" {
			names = append(names, name)
		}
	}

	sort.Strings(names)

	return names
}

// printable returns the body as text when it is text, and as hex otherwise.
// A plist body is the thing the plan's E1 pass line asks to see.
func printable(data []byte, limit int) string {
	if len(data) > limit {
		data = data[:limit]
	}

	for _, b := range data {
		if b == 0 || (b < 0x20 && b != '\n' && b != '\r' && b != '\t') {
			return "hex:" + hex.EncodeToString(data)
		}
	}

	return strings.Join(strings.Fields(string(data)), " ")
}

// guestString reads an NSString out of the guest through its UTF8String.
func (r *Runtime) guestString(object uint64) (string, error) {
	pointer, err := r.Invoke(object, "UTF8String")
	if err != nil {
		return "", err
	}

	if pointer == 0 {
		return "", nil
	}

	var out []byte

	for offset := uint64(0); offset < 8192; offset += 64 {
		chunk, err := r.engine.MemRead(pointer+offset, 64)
		if err != nil {
			break
		}

		if end := bytes.IndexByte(chunk, 0); end >= 0 {
			return string(append(out, chunk[:end]...)), nil
		}

		out = append(out, chunk...)
	}

	return string(out), nil
}

// guestData reads an NSData out of the guest.
func (r *Runtime) guestData(object uint64) ([]byte, error) {
	length, err := r.Invoke(object, "length")
	if err != nil {
		return nil, err
	}

	if length == 0 {
		return nil, nil
	}

	pointer, err := r.Invoke(object, "bytes")
	if err != nil {
		return nil, err
	}

	return r.engine.MemRead(pointer, length)
}
