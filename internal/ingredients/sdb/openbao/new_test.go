package openbao

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

// genCert writes a minimal self-signed cert/key pair (PEM) to certPath/
// keyPath, for exercising New() without a real CA.
func genCert(t *testing.T, certPath, keyPath string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshaling key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("writing cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("writing key: %v", err)
	}
}

func TestNew_Success(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")
	genCert(t, certPath, keyPath)

	p, err := New("https://vault.example.com:8200", certPath, keyPath, "", "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Addr != "https://vault.example.com:8200" {
		t.Errorf("Addr = %q", p.Addr)
	}
	if p.AuthMount != "cert" {
		t.Errorf("expected default auth mount %q, got %q", "cert", p.AuthMount)
	}
}

func TestNew_TrailingSlashTrimmed(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")
	genCert(t, certPath, keyPath)

	p, err := New("https://vault.example.com:8200/", certPath, keyPath, "", "myauth", "myrole")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Addr != "https://vault.example.com:8200" {
		t.Errorf("Addr = %q, want trailing slash trimmed", p.Addr)
	}
	if p.AuthMount != "myauth" || p.AuthRole != "myrole" {
		t.Errorf("AuthMount/AuthRole = %q/%q", p.AuthMount, p.AuthRole)
	}
}

func TestNew_WithCABundle(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")
	genCert(t, certPath, keyPath)
	caPath := certPath // any valid PEM cert works as a CA bundle for this test

	_, err := New("https://vault.example.com:8200", certPath, keyPath, caPath, "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNew_MissingRequiredFields(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")
	genCert(t, certPath, keyPath)

	cases := []struct {
		name            string
		addr, cert, key string
	}{
		{"missing addr", "", certPath, keyPath},
		{"missing cert", "https://vault.example.com", "", keyPath},
		{"missing key", "https://vault.example.com", certPath, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.addr, tc.cert, tc.key, "", "", ""); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestNew_BadCertFiles(t *testing.T) {
	dir := t.TempDir()
	if _, err := New("https://vault.example.com", filepath.Join(dir, "nope.crt"), filepath.Join(dir, "nope.key"), "", "", ""); err == nil {
		t.Fatal("expected an error for missing cert/key files")
	}
}

func TestNew_BadCABundle(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")
	genCert(t, certPath, keyPath)

	badCA := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(badCA, []byte("not a cert"), 0o600); err != nil {
		t.Fatalf("writing bad CA bundle: %v", err)
	}
	if _, err := New("https://vault.example.com", certPath, keyPath, badCA, "", ""); err == nil {
		t.Fatal("expected an error for an invalid CA bundle")
	}
}

func TestNew_MissingCABundleFile(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")
	genCert(t, certPath, keyPath)

	if _, err := New("https://vault.example.com", certPath, keyPath, filepath.Join(dir, "nope.pem"), "", ""); err == nil {
		t.Fatal("expected an error for a missing CA bundle file")
	}
}

func TestFromEnv_Unset(t *testing.T) {
	t.Setenv(EnvAddr, "")
	t.Setenv(EnvClientCert, "")
	t.Setenv(EnvClientKey, "")

	p, err := FromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p != nil {
		t.Fatal("expected a nil provider when no env vars are set")
	}
}

func TestFromEnv_Configured(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")
	genCert(t, certPath, keyPath)

	t.Setenv(EnvAddr, "https://vault.example.com")
	t.Setenv(EnvClientCert, certPath)
	t.Setenv(EnvClientKey, keyPath)

	p, err := FromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p == nil {
		t.Fatal("expected a non-nil provider")
	}
}
