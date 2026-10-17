package sapbridge

import (
	"encoding/base64"
	"os"
	"testing"
)

// TestLiveSAPHandshake runs the real two-leg SAP handshake against Apple and
// signs a body through the public API. It needs the four Apple binaries in the
// asset cache (or BundleDir). Run explicitly:
//
//	go test -run TestLiveSAPHandshake -v .
func TestLiveSAPHandshake(t *testing.T) {
	// Honour an explicit asset directory so CI can run the live tests.
	if dir := os.Getenv("DSH_SAP_ASSET_DIR"); dir != "" {
		BundleDir = dir
	}

	hardware := []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}

	signer, err := New(
		"https://fpinit.itunes.apple.com/v1/signSapSetup/legacy",
		"https://s.mzstatic.com/sap/setupCert.plist",
		200,
		hardware,
	)
	if err != nil {
		t.Skipf("SAP handshake unavailable (assets or network): %v", err)
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
	blob, err := KBSync([]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, "1234567890")
	if err != nil {
		t.Skipf("kbsync unavailable (assets): %v", err)
	}
	if len(blob) < 64 {
		t.Fatalf("kbsync suspiciously short: %d bytes", len(blob))
	}
	t.Logf("kbsync=%d bytes head=%x", len(blob), blob[:8])
}
