package sapbridge

import (
        "context"
        "encoding/base64"
        "os"
        "strings"
        "testing"
)

// TestSerialNumberByteLayout pins the ent/download serialNumber encoding.
// It must stay base64(54 c8 b0 a9 88 ++ guid[2:]) or Apple rejects the request.
func TestSerialNumberByteLayout(t *testing.T) {
        got, err := SerialNumber([]byte{0xAA, 0xBB, 0x01, 0x02, 0x03, 0x04})
        if err != nil {
                t.Fatal(err)
        }

        // Independent recomputation so a wrong constant cannot pass by accident.
        want := base64.StdEncoding.EncodeToString([]byte{
                0x54, 0xc8, 0xb0, 0xa9, 0x88, 0x01, 0x02, 0x03, 0x04,
        })
        if got != want {
                t.Fatalf("SerialNumber = %q, want %q", got, want)
        }
}

func TestSerialNumberRejectsWrongLength(t *testing.T) {
        for _, size := range []int{0, 1, 5, 7, 8, 20} {
                if _, err := SerialNumber(make([]byte, size)); err == nil {
                        t.Fatalf("SerialNumber accepted %d bytes", size)
                }
        }
}

func TestGuidFromHardware(t *testing.T) {
        got := GuidFromHardware([]byte{0xa4, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6})
        if got != "A4B2C3D4E5F6" {
                t.Fatalf("GuidFromHardware = %q, want A4B2C3D4E5F6", got)
        }
}

func TestParseDSID(t *testing.T) {
        for _, tc := range []struct {
                in   string
                want int64
        }{{"1234567890", 1234567890}, {"0", 0}, {"  42 ", 42}} {
                got, err := ParseDSID(tc.in)
                if err != nil {
                        t.Fatalf("ParseDSID(%q): %v", tc.in, err)
                }
                if got != tc.want {
                        t.Fatalf("ParseDSID(%q) = %d, want %d", tc.in, got, tc.want)
                }
        }

        // ent/download needs a nonzero decimal DSID; these must be rejected.
        for _, bad := range []string{"", "abc", "-1", "1.5", "0x10"} {
                if _, err := ParseDSID(bad); err == nil {
                        t.Fatalf("ParseDSID(%q) unexpectedly succeeded", bad)
                }
        }
}

func TestKBSyncRejectsZeroDSID(t *testing.T) {
        if _, err := KBSync([]byte{1}, "0"); err == nil {
                t.Fatal("KBSync accepted a zero DSID")
        }
}

// TestNilSignerFailsClosed guards the iOS path: a torn-down signer must never
// silently produce an empty signature, because that would send an unsigned
// request and earn a 403.
func TestNilSignerFailsClosed(t *testing.T) {
        var s *Signer
        if _, err := s.Sign([]byte("x")); err == nil {
                t.Fatal("nil signer accepted Sign")
        }
        if _, err := s.SignatureHeaderValue([]byte("x")); err == nil {
                t.Fatal("nil signer accepted SignatureHeaderValue")
        }
        if s.Hardware() != nil {
                t.Fatal("nil signer returned hardware")
        }
        if err := s.Close(); err != nil {
                t.Fatalf("nil Close: %v", err)
        }
}

// TestNewRejectsBadHardware verifies the handshake is never attempted with an
// unusable identity, which would waste a network round trip.
func TestNewRejectsBadHardware(t *testing.T) {
        for _, hw := range [][]byte{nil, {}, make([]byte, 21), make([]byte, 64)} {
                if _, err := New("https://example.invalid", "https://example.invalid", 200, hw); err == nil {
                        t.Fatalf("New accepted a %d-byte hardware ID", len(hw))
                }
        }
}

// fakeActionSigner stands in for the emulator: the header encoding is what is
// under test, not the guest.
type fakeActionSigner struct {
        signature []byte
        err       error
}

func (f fakeActionSigner) Sign([]byte) ([]byte, error) { return f.signature, f.err }

func (f fakeActionSigner) KBSync(context.Context, uint64) ([]byte, error) { return nil, nil }

func (f fakeActionSigner) Close() error { return nil }

// TestSignatureHeaderValueIsSingleLine guards the HTTP header: a newline in the
// value is a header-injection bug.
//
// The previous version asserted that the constant string "base64 value" has no
// newline, which cannot fail and never touched the code it claimed to guard.
// This one signs bytes that are themselves newlines.
func TestSignatureHeaderValueIsSingleLine(t *testing.T) {
        raw := []byte{0x00, 0x0a, 0x0d, 0xff, 0x0a}
        signer := &Signer{inner: fakeActionSigner{signature: raw}}

        value, err := signer.SignatureHeaderValue([]byte("body"))
        if err != nil {
                t.Fatalf("SignatureHeaderValue: %v", err)
        }

        if strings.ContainsAny(value, "\r\n") {
                t.Fatalf("header value contains a line break: %q", value)
        }

        if want := base64.StdEncoding.EncodeToString(raw); value != want {
                t.Fatalf("value = %q, want %q", value, want)
        }
}

// TestSignatureHeaderValueFailsWhenClosed keeps the closed-signer contract the
// old test was actually checking.
func TestSignatureHeaderValueFailsWhenClosed(t *testing.T) {
        if _, err := (&Signer{}).SignatureHeaderValue([]byte("x")); err == nil {
                t.Fatal("expected an error from a closed signer")
        }
}

func TestSetBundleDirOverridesGlobal(t *testing.T) {
        previous := BundleDirValue()
        defer func() { BundleDir = ""; SetBundleDir(previous) }()

        BundleDir = ""
        SetBundleDir("/tmp/from-setter")
        if got := BundleDirValue(); got != "/tmp/from-setter" {
                t.Fatalf("BundleDirValue = %q, want /tmp/from-setter", got)
        }

        // The exported variable wins when both are set, matching the documented order.
        BundleDir = "/tmp/from-global"
        if got := BundleDirValue(); got != "/tmp/from-global" {
                t.Fatalf("BundleDirValue = %q, want /tmp/from-global", got)
        }
}

// TestKBSyncReturnsErrorWithoutAssets is the regression test for a CI failure:
// loadBundle used to panic, which crashed the test binary instead of letting
// the caller report a missing asset.
func TestKBSyncReturnsErrorWithoutAssets(t *testing.T) {
        // Point at an empty directory so the loader cannot find the binaries.
        dir := t.TempDir()
        previous := BundleDir
        defer func() { BundleDir = previous }()
        BundleDir = dir

        _, err := KBSync([]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, "1234567890")
        if err == nil {
                t.Fatal("KBSync succeeded with an empty asset directory")
        }
        if strings.Contains(err.Error(), "panic") {
                t.Fatalf("error mentions a panic: %v", err)
        }
}

// TestBundleDirValidationRejectsTruncatedFiles confirms a corrupt asset is
// reported as an integrity failure rather than an opaque handshake error.
func TestBundleDirValidationRejectsTruncatedFiles(t *testing.T) {
        dir := t.TempDir()
        // Right names, wrong contents: CoreFP must be 94842464 bytes.
        for _, name := range []string{"AppleMediaServices", "commerce", "CoreFP", "CoreFP.icxs"} {
                if err := os.WriteFile(dir+"/"+name, []byte("truncated"), 0o600); err != nil {
                        t.Fatal(err)
                }
        }

        previous := BundleDir
        defer func() { BundleDir = previous }()
        BundleDir = dir

        // Force SHA-256 verification on: by default the check is skipped
        // because iOS re-signs Mach-O files during install, changing their
        // bytes. In the test environment the files are not re-signed, so
        // the check should catch the truncation.
        t.Setenv("DSH_SAP_VERIFY", "1")

        _, err := KBSync([]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, "1234567890")
        if err == nil {
                t.Fatal("KBSync accepted truncated assets")
        }
        if !strings.Contains(err.Error(), "size") && !strings.Contains(err.Error(), "integrity") {
                t.Fatalf("error does not mention size or integrity: %v", err)
        }
}
