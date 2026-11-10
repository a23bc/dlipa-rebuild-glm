package sapbridge

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/a23bc/dlipa-rebuild/sapbridge/internal/storeauth"
)

// TestLiveAnisetteProof runs the anisette line end to end against Apple: the
// seven-piece v4 profile, the ADI machine under Unicorn, gsa's machine
// provisioning, the Store AMD proof inside AppleMediaServices, and one sign
// through the store runtime.
//
// This is the behavioural half of the shim merge. The merge compiles on
// Windows, but unicorn is not available there (see
// internal/sap/unicorn/library_windows.go), so nothing past the compiler can be
// proven on that host -- and on a non-jailbroken device the emulator has to be
// the no-JIT TCI build, which changes timing but not correctness. Linux with a
// stock libunicorn 2.1.4 is therefore the fastest place that can answer "does
// it actually produce the headers".
//
// No credentials are involved on purpose: the identity is a fresh random
// sixteen bytes, provisioning is the public startMachineProvisioning and
// finishMachineProvisioning pair, and the AMD proof asks a fixed test hardware
// id. Run it:
//
//	DLIPA_UNICORN_PATH=/path/to/libunicorn.so.2 DSH_SAP_REQUIRE_LIVE=1 \
//	  go test -run TestLiveAnisetteProof -v -timeout 35m ./
func TestLiveAnisetteProof(t *testing.T) {
	applyAssetDir()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	// A checkout holds no v4 profile, and this test exists to pay for it once
	// and say what it cost, so the fetch is allowed here instead of skipping.
	AllowAssetFetch()

	cost, err := FetchSapAssets()
	if err != nil {
		unavailable(t, err)
	}

	t.Logf("assets: %s", cost)

	proofStarted := time.Now()

	headers, state, err := storeauth.AnisetteHeaders(ctx, storeauth.NewHTTPClient(nil), nil)
	if err != nil {
		t.Fatalf("anisette proof: %v", err)
	}

	// Staged, because the whole run is the number nobody can act on: upstream
	// proved this same proof in six seconds on this same host and library, so
	// where our minutes go has to be named before a device run is proposed.
	first := time.Since(proofStarted).Round(time.Millisecond)

	// Every one of these has to arrive: the login request that Apple answers
	// with 204 and then 404 is missing them, so a partial set would read as a
	// pass while the sign-in still failed.
	for _, name := range []string{
		"X-Apple-I-MD", "X-Apple-I-MD-M", "X-Apple-I-MD-RINFO", "X-Apple-I-MD-LU",
		"X-Apple-I-SRL-NO", "X-Apple-I-Client-Time", "X-Apple-I-TimeZone",
		"X-Apple-Locale", "X-Mme-Device-Id", "X-MMe-Client-Info",
	} {
		if headers.Get(name) == "" {
			t.Errorf("missing anisette header %s", name)
		}
	}

	// The state has to be enough to prove again without provisioning: a proof
	// that cannot be persisted is one that has to be re-minted at gsa on every
	// sign-in, and that is the part with a rate limit.
	replayed, provisioned, err := storeauth.AnisetteHeaders(ctx, storeauth.NewHTTPClient(nil), state)
	if err != nil {
		t.Fatalf("replay persisted anisette state: %v", err)
	}

	t.Logf("timing: first proof %s, replay from state %s, state %d -> %d bytes",
		first, (time.Since(proofStarted) - first).Round(time.Millisecond), len(state), len(provisioned))

	if got, want := replayed.Get("X-Mme-Device-Id"), headers.Get("X-Mme-Device-Id"); got != want {
		t.Errorf("identity changed across a state round trip: %q then %q", want, got)
	}

	if replayed.Get("X-Apple-I-MD") == headers.Get("X-Apple-I-MD") {
		t.Error("two proofs produced the same one-time password")
	}

	hardware := []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}

	amdStarted := time.Now()

	amd, next, err := storeauth.StoreAMDHeaders(ctx, provisioned,
		"https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate", hardware)
	if err != nil {
		// The timing travels with the failure on purpose: this axis fails for
		// upstream too, and the minutes it costs are still the number that
		// decides whether an emulator open belongs on the sign-in path at all.
		t.Fatalf("Store AMD proof after %s: %v", time.Since(amdStarted).Round(time.Millisecond), err)
	}

	for _, name := range []string{"X-Apple-AMD", "X-Apple-AMD-M"} {
		if amd[name] == "" {
			t.Errorf("missing Store AMD header %s", name)
		}
	}

	t.Logf("amd proof %d + %d chars, state %d -> %d bytes",
		len(amd["X-Apple-AMD"]), len(amd["X-Apple-AMD-M"]), len(provisioned), len(next))

	// The merged hook table also serves the store runtime, so the proof is not
	// finished until the sign that works on a device still works here. This is
	// the regression check for _IOServiceGetMatchingService answering 1 instead
	// of the MaxUint32 this repository used before the merge.
	signer, err := New(
		"https://fpinit.itunes.apple.com/v1/signSapSetup/legacy",
		"https://s.mzstatic.com/sap/setupCert.plist",
		200,
		hardware,
	)
	if err != nil {
		t.Fatalf("open SAP signer: %v", err)
	}

	defer signer.Close()

	body := []byte("<?xml version=\"1.0\"?><plist version=\"1.0\"><dict>" +
		"<key>attempt</key><string>1</string>" +
		"<key>guid</key><string>" + GuidFromHardware(hardware) + "</string>" +
		"<key>rmp</key><string>0</string>" +
		"<key>why</key><string>signIn</string>" +
		"</dict></plist>")

	value, err := signer.SignatureHeaderValue(body)
	if err != nil {
		t.Fatalf("sign with the merged hook table: %v", err)
	}

	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		t.Fatalf("signature is not valid base64: %v", err)
	}

	// Device run 497 measured this at 668 bytes for a 461-byte body. The count
	// is the criterion, not the value: an SAP session is stateful, so two
	// signatures over the same body are expected to differ.
	t.Logf("signature %d bytes from a %d byte body (device baseline 668)", len(decoded), len(body))
}
