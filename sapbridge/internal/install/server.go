package install

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Server hands a local package to the system installer over itms-services.
//
// The installer is a separate process on the same device: it reads a manifest
// from a URL and then fetches the package. Both have to stay reachable while the
// install runs, which is why the server lives in the app and outlives the call
// that starts it.
//
// TLS is self-signed by necessity -- nothing issues a certificate for a loopback
// address. The certificate is generated once and kept, because iOS remembers
// trust per certificate and a fresh one each launch would mean installing the
// profile again each launch.
type Server struct {
	server *http.Server
	guide  *http.Server
}

// Manifest describes the package for the installer.
type Manifest struct {
	BundleID    string
	Version     string
	Title       string
	PackagePath string
}

// Start serves the manifest and the package on the loopback interface and returns
// the itms-services URL to open, plus the page that explains how to trust the
// certificate when that has not happened yet.
func Start(dataDir string, manifest Manifest) (*Server, string, string, error) {
	if manifest.PackagePath == "" {
		return nil, "", "", fmt.Errorf("install: no package to serve")
	}

	if _, err := os.Stat(manifest.PackagePath); err != nil {
		return nil, "", "", fmt.Errorf("install: package: %w", err)
	}

	certificate, caPEM, err := loadOrCreateCertificate(dataDir)
	if err != nil {
		return nil, "", "", err
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", "", fmt.Errorf("install: listen: %w", err)
	}

	port := listener.Addr().(*net.TCPAddr).Port

	// The installer wants HTTPS, and a certificate for a bare IP address is
	// awkward; localhost.direct resolves to 127.0.0.1, so the URL carries a proper
	// host name while the socket stays on the loopback interface.
	base := fmt.Sprintf("https://localhost.direct:%d", port)

	server := &Server{}

	mux := http.NewServeMux()

	// The installer asks for the manifest by the URL it was given, then fetches
	// whatever asset URLs that manifest names -- both come back here.
	mux.HandleFunc("/manifest.plist", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write(manifestPlist(manifest, base))
	})

	mux.HandleFunc("/app.ipa", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		http.ServeFile(w, r, manifest.PackagePath)
	})

	mux.HandleFunc("/ca.pem", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write(caPEM)
	})

	server.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{certificate},
			MinVersion:   tls.VersionTLS12,
		},
	}

	go func() { _ = server.server.ServeTLS(listener, "", "") }()

	// The guide has to be reachable before anything is trusted, so it is served
	// over plain HTTP: a page delivered over a handshake that is failing cannot
	// explain how to fix that handshake.
	guideListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = server.server.Close()

		return nil, "", "", fmt.Errorf("install: guide listener: %w", err)
	}

	guidePort := guideListener.Addr().(*net.TCPAddr).Port
	guideURL := fmt.Sprintf("http://localhost.direct:%d/", guidePort)

	guideMux := http.NewServeMux()
	guideMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(guideHTML(base)))
	})
	guideMux.HandleFunc("/profile.mobileconfig", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-apple-aspen-config")
		w.Header().Set("Content-Disposition", `attachment; filename="DLiPA.mobileconfig"`)
		_, _ = w.Write(mobileConfig(caPEM))
	})

	server.guide = &http.Server{Handler: guideMux, ReadHeaderTimeout: 10 * time.Second}

	go func() { _ = server.guide.Serve(guideListener) }()

	installURL := "itms-services://?action=download-manifest&url=" +
		strings.ReplaceAll(base+"/manifest.plist", ":", "%3A")

	return server, installURL, guideURL, nil
}

// Stop shuts both listeners down.
func (s *Server) Stop() {
	if s == nil {
		return
	}

	if s.server != nil {
		_ = s.server.Close()
	}

	if s.guide != nil {
		_ = s.guide.Close()
	}
}

// manifestPlist renders the document the installer reads.
func manifestPlist(m Manifest, base string) []byte {
	title := m.Title
	if title == "" {
		title = m.BundleID
	}

	version := m.Version
	if version == "" {
		version = "1.0"
	}

	return []byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>items</key>
	<array>
		<dict>
			<key>assets</key>
			<array>
				<dict>
					<key>kind</key>
					<string>software-package</string>
					<key>url</key>
					<string>%s/app.ipa</string>
				</dict>
			</array>
			<key>metadata</key>
			<dict>
				<key>bundle-identifier</key>
				<string>%s</string>
				<key>bundle-version</key>
				<string>%s</string>
				<key>kind</key>
				<string>software</string>
				<key>title</key>
				<string>%s</string>
			</dict>
		</dict>
	</array>
</dict>
</plist>
`, base, xmlEscape(m.BundleID), xmlEscape(version), xmlEscape(title)))
}

// xmlEscape keeps a package name with an ampersand from breaking the plist.
func xmlEscape(value string) string {
	replacer := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;")

	return replacer.Replace(value)
}

// guideHTML is the four-step page shown when the certificate is not trusted.
func guideHTML(base string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html><head><meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{font:16px -apple-system;margin:24px;line-height:1.65}code{background:#f0f0f0;padding:2px 4px;border-radius:4px}</style>
</head><body>
<h2>Trust the local certificate</h2>
<ol>
<li><a href="/profile.mobileconfig">Download the profile</a></li>
<li>Settings &rarr; Profile Downloaded &rarr; Install (enter the passcode)</li>
<li>Settings &rarr; General &rarr; About &rarr; Certificate Trust Settings</li>
<li>Turn on full trust for <b>DLiPA CA</b>, come back here and install again</li>
</ol>
<p>The certificate is generated on this device and never leaves it. The installer
refuses <code>%s</code> until step 4 is done.</p>
</body></html>`, base)
}

// mobileConfig wraps the CA certificate in a profile the user can install.
func mobileConfig(caPEM []byte) []byte {
	block, _ := pem.Decode(caPEM)
	if block == nil {
		return nil
	}

	encoded := base64.StdEncoding.EncodeToString(block.Bytes)

	return []byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>PayloadCertificateFileName</key>
			<string>DLiPA.cer</string>
			<key>PayloadContent</key>
			<data>%s</data>
			<key>PayloadDescription</key>
			<string>DLiPA local install certificate</string>
			<key>PayloadDisplayName</key>
			<string>DLiPA CA</string>
			<key>PayloadIdentifier</key>
			<string>com.a23bc.dliparebuild.ca</string>
			<key>PayloadType</key>
			<string>com.apple.security.root</string>
			<key>PayloadUUID</key>
			<string>%s</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
		</dict>
	</array>
	<key>PayloadDisplayName</key>
	<string>DLiPA local install</string>
	<key>PayloadIdentifier</key>
	<string>com.a23bc.dliparebuild.profile</string>
	<key>PayloadRemovalDisallowed</key>
	<false/>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>%s</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
</dict>
</plist>
`, encoded, newUUID(), newUUID()))
}

// newUUID is the profile identity iOS uses to remember the install.
func newUUID() string {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return "00000000-0000-4000-8000-000000000000"
	}

	buffer[6] = (buffer[6] & 0x0f) | 0x40
	buffer[8] = (buffer[8] & 0x3f) | 0x80

	return fmt.Sprintf("%X-%X-%X-%X-%X",
		buffer[0:4], buffer[4:6], buffer[6:8], buffer[8:10], buffer[10:16])
}

// loadOrCreateCertificate returns a leaf certificate and its CA in PEM,
// generating both the first time.
//
// The certificate is stored rather than regenerated: iOS remembers trust per
// certificate, so a new one on every launch would ask the user to install the
// profile each time.
func loadOrCreateCertificate(dataDir string) (tls.Certificate, []byte, error) {
	certPath := filepath.Join(dataDir, "install-cert.pem")
	keyPath := filepath.Join(dataDir, "install-key.pem")
	caPath := filepath.Join(dataDir, "install-ca.pem")

	if existing, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		if caPEM, err := os.ReadFile(caPath); err == nil && leafLifetimeOK(existing) {
			// The fingerprint is what the user can compare against the profile in
			// Settings: a mismatch means the installed profile belongs to an older
			// certificate, which is exactly how "I trusted it already" happens.
			fmt.Fprintf(os.Stderr, "[SAP] install: reusing CA %s\n", fingerprint(caPEM))

			return existing, caPEM, nil
		}
	}

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("install: ca key: %w", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: serial(),
		// The original certificate's shape, matched field for field: a leaf without
		// an authority key identifier is the kind iOS declines to chain, and the
		// validity ceiling is Apple's, not a preference.
		Subject: pkix.Name{
			CommonName:   "DLiPA CA",
			Organization: []string{"LocalCA"},
			Locality:     []string{"Local"},
			Province:     []string{"Local"},
			Country:      []string{"US"},
		},
		SubjectKeyId:          keyIdentifier(caKey.PublicKey),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(0, 0, caValidityDays),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("install: ca cert: %w", err)
	}

	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("install: parse ca: %w", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("install: leaf key: %w", err)
	}

	leafTemplate := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: "localhost.direct"},
		NotBefore:    time.Now().Add(-time.Hour),
		// 365 days, not ten years. Apple refuses TLS server certificates with a
		// lifetime over 825 days, and that rule applies to certificates issued by a
		// user-installed root as well -- a ten year leaf is rejected even when the
		// root is trusted, which is exactly how this failed with a profile installed.
		NotAfter:    time.Now().AddDate(0, 0, 365),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:    []string{"localhost.direct", "localhost"},
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("install: leaf cert: %w", err)
	}

	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})

	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("install: marshal key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("install: data dir: %w", err)
	}

	for path, content := range map[string][]byte{
		certPath: leafPEM,
		keyPath:  keyPEM,
		caPath:   caPEM,
	} {
		if err := os.WriteFile(path, content, 0o600); err != nil {
			return tls.Certificate{}, nil, fmt.Errorf("install: write %s: %w", filepath.Base(path), err)
		}
	}

	fmt.Fprintf(os.Stderr, "[SAP] install: generated CA %s\n", fingerprint(caPEM))

	// The chain is sent, not just the leaf: iOS can usually find an installed root on
	// its own, but a locally trusted one is the case where trusting to build the
	// chain by itself has bitten before.
	certificate := tls.Certificate{
		Certificate: [][]byte{leafDER, caDER},
		PrivateKey:  leafKey,
		Leaf:        mustParse(leafDER),
	}

	return certificate, caPEM, nil
}

func serial() *big.Int {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)

	value, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return big.NewInt(time.Now().UnixNano())
	}

	return value
}

// fingerprint is the SHA-256 of the certificate, short enough to read out loud.
func fingerprint(caPEM []byte) string {
	block, _ := pem.Decode(caPEM)
	if block == nil {
		return "unknown"
	}

	sum := sha256.Sum256(block.Bytes)

	return fmt.Sprintf("%X", sum[:8])
}

// leafLifetimeOK reports whether a stored certificate may still be presented.
//
// Two things disqualify it: it has expired, or it was issued with a lifetime Apple
// no longer accepts. The second is why an existing install has to regenerate once --
// the first leaves were ten year ones.
func leafLifetimeOK(certificate tls.Certificate) bool {
	leaf := certificate.Leaf
	if leaf == nil && len(certificate.Certificate) > 0 {
		leaf = mustParse(certificate.Certificate[0])
	}

	if leaf == nil {
		return false
	}

	const limit = 825 * 24 * time.Hour

	if leaf.NotAfter.Sub(leaf.NotBefore) > limit {
		return false
	}

	return time.Now().Before(leaf.NotAfter)
}

func mustParse(der []byte) *x509.Certificate {
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil
	}

	return parsed
}

const (
	// Apple's ceiling for TLS server certificates, and what the original uses.
	leafValidityDays = 825
	caValidityDays   = 3650
)

// keyIdentifier is the RFC 5280 method 1 key identifier: SHA-1 over the public key
// bits, twenty bytes. iOS expects both the CA and the leaf to carry one.
func keyIdentifier(public any) []byte {
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return nil
	}

	sum := sha1.Sum(der)

	return sum[:]
}
