package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTLSConfigIsEnabled(t *testing.T) {
	tests := []struct {
		name string
		cfg  TLSConfig
		want bool
	}{
		{"empty", TLSConfig{}, false},
		{"cert only", TLSConfig{CertFile: "cert.pem"}, false},
		{"key only", TLSConfig{KeyFile: "key.pem"}, false},
		{"cert+key", TLSConfig{CertFile: "cert.pem", KeyFile: "key.pem"}, true},
		{"domain", TLSConfig{Domains: []string{"example.com"}}, true},
		{"domain+cert", TLSConfig{CertFile: "c", KeyFile: "k", Domains: []string{"example.com"}}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.IsEnabled(); got != tt.want {
				t.Errorf("IsEnabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTLSConfigIsACME(t *testing.T) {
	tests := []struct {
		name string
		cfg  TLSConfig
		want bool
	}{
		{"empty", TLSConfig{}, false},
		{"manual", TLSConfig{CertFile: "c", KeyFile: "k"}, false},
		{"acme", TLSConfig{Domains: []string{"example.com"}}, true},
		{"acme multi", TLSConfig{Domains: []string{"a.com", "b.com"}}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.IsACME(); got != tt.want {
				t.Errorf("IsACME() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBuildTLSConfigManual(t *testing.T) {
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")

	certPEM, keyPEM := generateTestCert(t)
	os.WriteFile(certFile, certPEM, 0644)
	os.WriteFile(keyFile, keyPEM, 0600)

	cfg := &TLSConfig{
		CertFile: certFile,
		KeyFile:  keyFile,
	}

	tlsConfig, err := cfg.BuildTLSConfig()
	if err != nil {
		t.Fatalf("BuildTLSConfig() error: %v", err)
	}

	if tlsConfig == nil {
		t.Fatal("expected non-nil tls.Config")
	}
	if len(tlsConfig.Certificates) != 1 {
		t.Errorf("expected 1 certificate, got %d", len(tlsConfig.Certificates))
	}
	if tlsConfig.MinVersion != 0x0303 { // tls.VersionTLS12
		t.Errorf("MinVersion = %x, want TLS 1.2 (0x0303)", tlsConfig.MinVersion)
	}
}

func TestBuildTLSConfigMissingCert(t *testing.T) {
	cfg := &TLSConfig{
		CertFile: "/nonexistent/cert.pem",
		KeyFile:  "/nonexistent/key.pem",
	}

	_, err := cfg.BuildTLSConfig()
	if err == nil {
		t.Fatal("expected error for missing cert file")
	}
}

func TestBuildTLSConfigMissingKey(t *testing.T) {
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	os.WriteFile(certFile, []byte("fake"), 0644)

	cfg := &TLSConfig{
		CertFile: certFile,
		KeyFile:  "/nonexistent/key.pem",
	}

	_, err := cfg.BuildTLSConfig()
	if err == nil {
		t.Fatal("expected error for missing key file")
	}
}

func TestBuildTLSConfigACME(t *testing.T) {
	tmpDir := t.TempDir()
	cacheDir := filepath.Join(tmpDir, "certs")

	cfg := &TLSConfig{
		Domains:  []string{"test.example.com"},
		CacheDir: cacheDir,
	}

	tlsConfig, err := cfg.BuildTLSConfig()
	if err != nil {
		t.Fatalf("BuildTLSConfig() error: %v", err)
	}

	if tlsConfig == nil {
		t.Fatal("expected non-nil tls.Config")
	}

	// Cache dir should have been created
	if _, err := os.Stat(cacheDir); os.IsNotExist(err) {
		t.Error("cache directory should have been created")
	}

	// ACME config should have GetCertificate set
	if tlsConfig.GetCertificate == nil {
		t.Error("ACME tls.Config should have GetCertificate set")
	}
}

func TestBuildTLSConfigACMEWithEmail(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &TLSConfig{
		Domains:  []string{"example.com", "api.example.com"},
		CacheDir: filepath.Join(tmpDir, "certs"),
		Email:    "admin@example.com",
	}

	tlsConfig, err := cfg.BuildTLSConfig()
	if err != nil {
		t.Fatalf("BuildTLSConfig() error: %v", err)
	}

	if tlsConfig == nil {
		t.Fatal("expected non-nil tls.Config")
	}
}

func TestBuildTLSConfigNoConfig(t *testing.T) {
	cfg := &TLSConfig{}

	_, err := cfg.BuildTLSConfig()
	if err == nil {
		t.Fatal("expected error for empty TLS config")
	}
}

func TestHTTPRedirectHandler(t *testing.T) {
	h := httpRedirectHandler()
	if h == nil {
		t.Fatal("httpRedirectHandler() returned nil")
	}
}

// generateTestCert creates a self-signed EC cert/key pair for testing.
func generateTestCert(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshaling key: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM
}
