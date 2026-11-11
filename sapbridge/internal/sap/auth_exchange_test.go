package sap

import (
	"bytes"
	"testing"
)

// The endpoint is the one place an Apple ID password leaves this process, so
// the rule is pinned rather than trusted: https, the store host family, and the
// authenticate selector -- nothing else.
func TestValidateAuthenticateEndpoint(t *testing.T) {
	accepted := []string{
		"https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate",
		"https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate/",
		"https://p47-buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate/",
		"https://p47-buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate/?Pod=47&PRH=47",
		"https://buy.itunes.apple.com:443/WebObjects/MZFinance.woa/wa/authenticate",
	}

	for _, value := range accepted {
		if _, err := validateAuthenticateEndpoint(value); err != nil {
			t.Errorf("accepted endpoint refused: %s: %v", value, err)
		}
	}

	refused := []string{
		"http://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate",
		"https://buy.itunes.apple.com:8443/WebObjects/MZFinance.woa/wa/authenticate",
		"https://user:pass@buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate",
		"https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate#x",
		"https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/logout",
		"https://buy.itunes.apple.com.evil.example/WebObjects/MZFinance.woa/wa/authenticate",
		"https://evilbuy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate",
		"https://p47-buy.itunes.apple.com.evil.example/WebObjects/MZFinance.woa/wa/authenticate",
		"https://example.com/WebObjects/MZFinance.woa/wa/authenticate",
		"not a url",
	}

	for _, value := range refused {
		if _, err := validateAuthenticateEndpoint(value); err == nil {
			t.Errorf("endpoint accepted that must not be: %s", value)
		}
	}
}

func TestParseHardwareGUID(t *testing.T) {
	got, err := parseHardwareGUID("010203040506")
	if err != nil {
		t.Fatalf("valid guid refused: %v", err)
	}

	if !bytes.Equal(got, []byte{1, 2, 3, 4, 5, 6}) {
		t.Fatalf("guid decoded to %v", got)
	}

	if _, err := parseHardwareGUID("0102030405"); err == nil {
		t.Fatal("five bytes accepted")
	}

	if _, err := parseHardwareGUID("zzzzzzzzzzzz"); err == nil {
		t.Fatal("non-hex accepted")
	}

	if _, err := parseHardwareGUID(""); err == nil {
		t.Fatal("empty guid accepted")
	}
}
