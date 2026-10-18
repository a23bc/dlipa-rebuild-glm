package sapbridge

import (
	"encoding/base64"
	"os"
	"strings"
	"testing"
)

// requireLive reports whether an unavailable SAP runtime must fail instead of
// skip.
//
// The default is to skip: the four Apple binaries are not in this repository,
// so a checkout without them must not turn red. CI sets DSH_SAP_REQUIRE_LIVE
// because it does stage the assets, and a skip there would hide the only thing
// these tests exist to answer: whether the pinned macOS assets still complete a
// real handshake against Apple.
func requireLive() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("DSH_SAP_REQUIRE_LIVE"))) {
	case "1", "true", "yes":
		return true
	default:
		return false
	}
}

// unavailable skips, or fails when the runtime was required. A skip is the
// honest outcome when there is nothing to test against; it is a lie when the
// assets are present and the handshake still did not happen.
func unavailable(t *testing.T, err error) {
	t.Helper()

	if requireLive() {
		t.Fatalf("SAP runtime required but unavailable: %v", err)
	}

	t.Skipf("SAP runtime unavailable (assets or network): %v", err)
}

// applyAssetDir honours an explicit asset directory so each live test can be
// run on its own. Without it only whichever test happens to run first would
// see the staged binaries, and the rest would silently have nothing to load.
func applyAssetDir() {
	if dir := os.Getenv("DSH_SAP_ASSET_DIR"); dir != "" {
		BundleDir = dir
	}
}

// TestLiveSAPHandshake runs the real two-leg SAP handshake against Apple and
// signs a body through the public API. It needs the four Apple binaries in the
// asset cache (or BundleDir). Run explicitly:
//
//	go test -run TestLiveSAPHandshake -v .
func TestLiveSAPHandshake(t *testing.T) {
	applyAssetDir()

	hardware := []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}

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

	value, err := signer.SignatureHeaderValue(body)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		t.Fatalf("signature is not valid base64: %v", err)
	}
	if len(decoded) < 256 {
		t.Fatalf("signature suspiciously short: %d bytes", len(decoded))
	}

	// Two signatures over the same body must differ: the SAP session is stateful.
	second, err := signer.SignatureHeaderValue(body)
	if err != nil {
		t.Fatalf("second sign: %v", err)
	}
	if second == value {
		t.Fatal("two signatures over the same body are identical")
	}

	t.Logf("body=%d bytes signature=%d bytes (base64 %d chars)",
		len(body), len(decoded), len(value))
}

// TestLiveKBSync generates a real FairPlay blob through the public API.
func TestLiveKBSync(t *testing.T) {
	applyAssetDir()

	blob, err := KBSync([]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, "1234567890")
	if err != nil {
		unavailable(t, err)
	}
	if len(blob) < 64 {
		t.Fatalf("kbsync suspiciously short: %d bytes", len(blob))
	}
	t.Logf("kbsync=%d bytes head=%x", len(blob), blob[:8])
}
