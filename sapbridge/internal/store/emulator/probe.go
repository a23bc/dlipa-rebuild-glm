package emulator

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
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
	method := ""

	if value, err := r.Invoke(request, "HTTPMethod"); err == nil && value != 0 {
		method, _ = r.guestString(value)
	}

	address := ""

	if value, err := r.Invoke(request, "URL"); err == nil && value != 0 {
		if absolute, err := r.Invoke(value, "absoluteString"); err == nil && absolute != 0 {
			address, _ = r.guestString(absolute)
		}
	}

	bodyLength := 0
	bodyHead := ""

	if value, err := r.Invoke(request, "HTTPBody"); err == nil && value != 0 {
		if data, err := r.guestData(value); err == nil {
			bodyLength = len(data)

			head := data
			if len(head) > 48 {
				head = head[:48]
			}

			bodyHead = hex.EncodeToString(head)
		}
	}

	headers := 0

	if value, err := r.Invoke(request, "allHTTPHeaderFields"); err == nil && value != 0 {
		if count, err := r.Invoke(value, "count"); err == nil {
			headers = int(count)
		}
	}

	return fmt.Sprintf("method=%s url=%s body=%d head=%s headers=%d",
		method, address, bodyLength, bodyHead, headers), nil
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
