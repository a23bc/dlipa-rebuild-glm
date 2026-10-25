package emulator

import (
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
	// Reported by initWithBag: on device. Checked here so the log says whether
	// the page is mapped *before* the encoder is built, which separates "we
	// never mapped it" from "something unmapped it afterwards".
	if probe, readErr := r.engine.MemRead(0x1a2a0621c, 4); readErr != nil {
		fmt.Fprintf(os.Stderr, "[SAP] probe: 0x1a2a0621c UNREADABLE: %v\n", readErr)
	} else {
		fmt.Fprintf(os.Stderr, "[SAP] probe: 0x1a2a0621c readable %x\n", probe)
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
		return 0, fmt.Errorf("encoder setAccount: %w", err)
	}

	promise, err := r.Invoke(encoder, "requestWithMethod:URL:parameters:",
		4, r.New("NSURL", endpoint), r.importValue(parameters))
	if err != nil {
		return 0, fmt.Errorf("requestWithMethod:URL:parameters:: %w", err)
	}

	address, err := r.resolveAddress(promise)
	if err != nil {
		return 0, fmt.Errorf("resolve promise: %w", err)
	}

	return address, nil
}

// dumpFaultState reports what the guest looks like at the moment a call faulted.
//
// The guest faulted reading 0x1a2a0621c while uc_mem_read returned real bytes for
// the same address, and flushing the TLB changed nothing. Reading that address
// again after the fault separates "the page left" from "the translation never
// resolved", and the bytes at the reported PC say what the instruction wanted.
func (r *Runtime) dumpFaultState() {
	const faultAddr = 0x1a2a0621c
	const faultPC = 0x1a2b4cdac

	if after, err := r.engine.MemRead(faultAddr, 16); err != nil {
		fmt.Fprintf(os.Stderr, "[SAP] after fault: %#x unreadable: %v\n", faultAddr, err)
	} else {
		fmt.Fprintf(os.Stderr, "[SAP] after fault: %#x still readable %x\n", faultAddr, after)
	}

	if code, err := r.engine.MemRead(faultPC, 16); err != nil {
		fmt.Fprintf(os.Stderr, "[SAP] after fault: PC bytes unreadable: %v\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "[SAP] after fault: PC %#x code %x\n", faultPC, code)
	}
}
