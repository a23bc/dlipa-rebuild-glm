package sapbridge

import (
	"testing"

	"github.com/a23bc/dlipa-rebuild/sapbridge/internal/sap/machine"
)

// TestReportExternalCalls measures how many external symbols the SAP paths
// actually enter, as opposed to how many the binaries declare.
//
// The static import tables report 196, 976 and 289 symbols for CoreFP,
// AppleMediaServices and commerce. Those are declarations, and nearly all of
// them are never reached. Under dlopen the two numbers lead to completely
// different plans: a declared dependency has to exist at load time, while a
// weakly linked symbol that is actually called is a NULL pointer that crashes
// on first use. So the figure that decides whether dlopen is tractable is the
// dynamic one, and this is the only place it is measured.
//
// Run it where the assets exist:
//
//	DSH_SAP_ASSET_DIR=... go test -count=1 -run TestReportExternalCalls -v .
func TestReportExternalCalls(t *testing.T) {
	applyAssetDir()

	hardware := []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}

	// kbsync first. It is entirely local - no round trip to Apple - so its
	// numbers are always available, and it is the path that loads the
	// StoreAgent image on top of CoreFP and AppleMediaServices.
	machine.ResetExternalCalls()

	blob, err := KBSync(hardware, "1234567890")
	if err != nil {
		unavailable(t, err)
	}

	reportCalls(t, "kbsync", len(blob))

	// Then the handshake plus two signatures over the same body. Two, so the
	// per-signature cost is separable from the one-off setup cost.
	machine.ResetExternalCalls()

	signer, err := New(
		"https://fpinit.itunes.apple.com/v1/signSapSetup/legacy",
		"https://s.mzstatic.com/sap/setupCert.plist",
		200,
		hardware,
	)
	if err != nil {
		unavailable(t, err)
	}
	defer signer.Close()

	body := []byte("<?xml version=\"1.0\"?><plist version=\"1.0\"><dict>" +
		"<key>appleId</key><string>probe@example.invalid</string>" +
		"<key>attempt</key><string>1</string>" +
		"<key>guid</key><string>" + GuidFromHardware(hardware) + "</string>" +
		"<key>rmp</key><string>0</string>" +
		"<key>why</key><string>signIn</string>" +
		"</dict></plist>")

	for attempt := 1; attempt <= 2; attempt++ {
		if _, err := signer.SignatureHeaderValue(body); err != nil {
			t.Fatalf("sign %d: %v", attempt, err)
		}
	}

	reportCalls(t, "handshake + 2 signatures", 0)
}

func reportCalls(t *testing.T, label string, produced int) {
	t.Helper()

	calls := machine.ExternalCalls()

	var total uint64
	for _, call := range calls {
		total += call.Count
	}

	t.Logf("=== %s | %d distinct external symbols | %d calls ===",
		label, len(calls), total)
	for _, call := range calls {
		t.Logf("  %8d  %s", call.Count, call.Name)
	}

	if produced > 0 {
		t.Logf("=== %s produced %d bytes ===", label, produced)
	}
}
