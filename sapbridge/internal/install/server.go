package install

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Server hands a local package to the system installer over itms-services.
//
// The installer is a separate process on the same device: it reads a manifest
// from a URL and then fetches the package. Both have to be reachable while the
// install runs, which is why the server lives in the app and keeps running after
// the URL is opened.
//
// TLS is self-signed by necessity -- there is no certificate authority that will
// issue for 127.0.0.1. The certificate is generated once and kept, so the
// profile the user trusts does not have to be installed again after a relaunch.
type Server struct {
	mu       sync.Mutex
	listener net.Listener
	server   *http.Server
	caPath   string
}

// Manifest describes the package for the installer.
type Manifest struct {
	BundleID string
	Version  string
	Title    string
	// PackagePath is the .ipa on disk.
	PackagePath string
}

// Start serves the manifest and the package on the loopback interface and returns
// the itms-services URL to open.
func Start(dataDir string, manifest Manifest) (*Server, string, error) {
	if manifest.PackagePath == "" {
		return nil, "", fmt.Errorf("install: no package to serve")
	}

	if _, err := os.Stat(manifest.PackagePath); err != nil {
		return nil, "", fmt.Errorf("install: package: %w", err)
	}

	certificate, caPEM, err := loadOrCreateCertificate(dataDir)
	if err != nil {
		return nil, "", err
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", fmt.Errorf("install: listen: %w", err)
	}

	port := listener.Addr().(*net.TCPAddr).Port
	base := fmt.Sprintf("https://127.0.0.1:%d", port)

	server := &Server{listener: listener, caPath: filepath.Join(dataDir, "install-ca.pem")}

	mux := http.NewServeMux()

	// The installer asks for the manifest by the URL given to it, then fetches
	// whatever asset URLs that manifest names -- both come back here.
	mux.HandleFunc("/manifest.plist", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write(manifestPlist(manifest, base))
	})

	mux.HandleFunc("/app.ipa", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		http.ServeFile(w, r, manifest.PackagePath)
	})

	// iOS fetches the certificate from the same host before it will talk TLS in
	// some flows; serving it here saves a separate transfer when it does.
	mux.HandleFunc("/ca.pem", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write(caPEM)
	})

	server.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12},
	}

	go func() { _ = server.server.ServeTLS(listener, "", "") }()

	url := "itms-services://?action=download-manifest&url=" +
		strings.ReplaceAll(base+"/manifest.plist", ":", "%3A")

	return server, url, nil
}

// Stop shuts the server down.
func (s *Server) Stop() {
	if s == nil || s.server == nil {
		return
	}

	_ = s.server.Close()
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
`, base, m.BundleID, version, title))
}

// loadOrCreateCertificate returns a leaf certificate for 127.0.0.1 and its CA in
// PEM, generating both the first time.
//
// The certificate is stored rather than regenerated: iOS remembers trust per
// certificate, and a new one on every launch would ask the user to install the
// profile again each time.
func loadOrCreateCertificate(dataDir string) (tls.Certificate, []byte, error) {
	certPath := filepath.Join(dataDir, "install-cert.pem")
	keyPath := filepath.Join(dataDir, "install-key.pem")
	caPath := filepath.Join(dataDir, "install-ca.pem")

	if existing, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		if caPEM, err := os.ReadFile(caPath); err == nil {
			return existing, caPEM, nil
		}
	}

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("install: ca key: %w", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "DLiPA Local Install CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
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
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
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

	certificate, err := tls.X509KeyPair(leafPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("install: key pair: %w", err)
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
