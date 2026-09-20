package certs

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gogrlx/grlx/v2/internal/config"
)

// setupTLSConfigDir sets config globals to use a temp directory for TLS
// cert tests, and resets any OpenBao lease tracked by a previous test.
func setupTLSConfigDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	config.RootCA = filepath.Join(dir, "rootCA.pem")
	config.CertFile = filepath.Join(dir, "cert.pem")
	config.KeyFile = filepath.Join(dir, "key.pem")
	config.CertHosts = []string{"localhost", "127.0.0.1"}
	config.FarmerOrganization = "grlx-test"
	config.CertificateValidTime = 24 * time.Hour
	rememberLease("")
	return dir
}

// setupNKeyConfigDir sets config globals to use a temp directory for NKey tests.
func setupNKeyConfigDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	config.NKeyFarmerPrivFile = filepath.Join(dir, "farmer.nkey")
	config.NKeyFarmerPubFile = filepath.Join(dir, "farmer.pub")
	config.NKeySproutPrivFile = filepath.Join(dir, "sprout.nkey")
	config.NKeySproutPubFile = filepath.Join(dir, "sprout.pub")
	return dir
}

// --- OpenBao integration test scaffolding -----------------------------
//
// These tests need a running OpenBao (or Vault-API-compatible) dev
// server. Start one locally with:
//
//	bao server -dev -dev-root-token-id=root
//
// and the tests will find it at http://127.0.0.1:8200 by default; point
// them elsewhere with GRLX_CERTS_TEST_OPENBAO_ADDR /
// GRLX_CERTS_TEST_OPENBAO_TOKEN. Each test mounts its own throwaway PKI
// backend (unmounted on cleanup) so tests don't interfere with each
// other or require any pre-existing server configuration. When no dev
// server is reachable, these tests skip rather than fail, so `go test
// ./...` still passes in environments without OpenBao available.

const (
	testOpenBaoAddrEnv  = "GRLX_CERTS_TEST_OPENBAO_ADDR"
	testOpenBaoTokenEnv = "GRLX_CERTS_TEST_OPENBAO_TOKEN"
)

func obAdminRequest(t *testing.T, addr, token, method, path string, body any) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal openbao admin request body: %v", err)
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, addr+path, reader)
	if err != nil {
		t.Fatalf("build openbao admin request: %v", err)
	}
	req.Header.Set("X-Vault-Token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("openbao admin request %s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		t.Fatalf("openbao admin request %s %s failed: status %d: %s", method, path, resp.StatusCode, string(data))
	}
}

// setupOpenBaoPKI mounts a fresh PKI secrets engine and a permissive test
// role on a local OpenBao dev server, points the certs package at it via
// the GRLX_CERTS_OPENBAO_* environment variables, and skips the test if
// no dev server is reachable.
func setupOpenBaoPKI(t *testing.T) {
	t.Helper()
	addr := os.Getenv(testOpenBaoAddrEnv)
	if addr == "" {
		addr = "http://127.0.0.1:8200"
	}
	token := os.Getenv(testOpenBaoTokenEnv)
	if token == "" {
		token = "root"
	}

	healthClient := http.Client{Timeout: 2 * time.Second}
	resp, err := healthClient.Get(addr + "/v1/sys/health")
	if err != nil {
		t.Skipf("no local OpenBao dev server reachable at %s (start one with "+
			"`bao server -dev -dev-root-token-id=%s`): %v", addr, token, err)
	}
	resp.Body.Close()

	mount := fmt.Sprintf("pki-grlx-test-%d", time.Now().UnixNano())
	role := "grlx-test"

	obAdminRequest(t, addr, token, http.MethodPost, "/v1/sys/mounts/"+mount, map[string]string{"type": "pki"})
	t.Cleanup(func() {
		req, err := http.NewRequest(http.MethodDelete, addr+"/v1/sys/mounts/"+mount, nil)
		if err != nil {
			return
		}
		req.Header.Set("X-Vault-Token", token)
		if resp, err := http.DefaultClient.Do(req); err == nil {
			resp.Body.Close()
		}
	})
	obAdminRequest(t, addr, token, http.MethodPost, "/v1/sys/mounts/"+mount+"/tune",
		map[string]string{"max_lease_ttl": "720h"})
	obAdminRequest(t, addr, token, http.MethodPost, "/v1/"+mount+"/root/generate/internal",
		map[string]string{"common_name": "grlx-test-root", "ttl": "720h"})
	// Permissive role: these tests exercise the certs package's OpenBao
	// client, not OpenBao's own domain/IP allowlisting policy.
	obAdminRequest(t, addr, token, http.MethodPost, "/v1/"+mount+"/roles/"+role, map[string]any{
		"allow_any_name":    true,
		"allow_ip_sans":     true,
		"allow_subdomains":  true,
		"enforce_hostnames": false,
		"max_ttl":           "24h",
		"ttl":               "1h",
		"generate_lease":    true,
	})

	t.Setenv(EnvOpenBaoAddr, addr)
	t.Setenv(EnvOpenBaoToken, token)
	t.Setenv(EnvOpenBaoPKIMount, mount)
	t.Setenv(EnvOpenBaoRole, role)
}

// setupOpenBaoTLS combines setupTLSConfigDir and setupOpenBaoPKI for the
// common case of a test that needs both.
func setupOpenBaoTLS(t *testing.T) string {
	t.Helper()
	dir := setupTLSConfigDir(t)
	setupOpenBaoPKI(t)
	return dir
}

func TestGenCACertOpenBao(t *testing.T) {
	setupOpenBaoTLS(t)

	if err := genCACert(); err != nil {
		t.Fatalf("genCACert failed: %v", err)
	}

	certBytes, err := os.ReadFile(config.RootCA)
	if err != nil {
		t.Fatalf("failed to read CA cert: %v", err)
	}
	block, _ := pem.Decode(certBytes)
	if block == nil {
		t.Fatal("failed to decode CA cert PEM")
	}
	if block.Type != "CERTIFICATE" {
		t.Fatalf("expected CERTIFICATE PEM block, got %s", block.Type)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse CA certificate: %v", err)
	}
	if !cert.IsCA {
		t.Fatal("fetched certificate should be a CA")
	}
}

func TestGenCACertIdempotentOpenBao(t *testing.T) {
	setupOpenBaoTLS(t)

	if err := genCACert(); err != nil {
		t.Fatalf("genCACert failed: %v", err)
	}
	orig, err := os.ReadFile(config.RootCA)
	if err != nil {
		t.Fatalf("failed to read CA cert: %v", err)
	}

	if err := genCACert(); err != nil {
		t.Fatalf("genCACert second call failed: %v", err)
	}
	again, err := os.ReadFile(config.RootCA)
	if err != nil {
		t.Fatalf("failed to read CA cert after second call: %v", err)
	}

	if !bytes.Equal(orig, again) {
		t.Fatal("genCACert should fetch the same stable CA certificate on each call")
	}
}

func TestGenCertOpenBao(t *testing.T) {
	setupOpenBaoTLS(t)

	if err := GenCert(); err != nil {
		t.Fatalf("GenCert failed: %v", err)
	}

	certBytes, err := os.ReadFile(config.CertFile)
	if err != nil {
		t.Fatalf("failed to read server cert: %v", err)
	}
	block, _ := pem.Decode(certBytes)
	if block == nil {
		t.Fatal("failed to decode server cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse server certificate: %v", err)
	}
	if cert.IsCA {
		t.Fatal("server certificate should not be a CA")
	}

	foundLocalhost := false
	for _, name := range cert.DNSNames {
		if name == "localhost" {
			foundLocalhost = true
		}
	}
	if !foundLocalhost {
		t.Fatal("server cert should have localhost in DNSNames")
	}
	foundIP := false
	for _, ip := range cert.IPAddresses {
		if ip.String() == "127.0.0.1" {
			foundIP = true
		}
	}
	if !foundIP {
		t.Fatal("server cert should have 127.0.0.1 in IPAddresses")
	}

	keyBytes, err := os.ReadFile(config.KeyFile)
	if err != nil {
		t.Fatalf("failed to read server key: %v", err)
	}
	if block, _ := pem.Decode(keyBytes); block == nil {
		t.Fatal("failed to decode server key PEM")
	}
	info, err := os.Stat(config.KeyFile)
	if err != nil {
		t.Fatalf("failed to stat key file: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected key file permissions 0600, got %o", info.Mode().Perm())
	}

	caBytes, err := os.ReadFile(config.RootCA)
	if err != nil {
		t.Fatalf("failed to read CA cert: %v", err)
	}
	caBlock, _ := pem.Decode(caBytes)
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		t.Fatalf("failed to parse CA cert: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots}); err != nil {
		t.Fatalf("server cert should verify against the OpenBao-issued CA: %v", err)
	}
}

func TestGenCertIdempotentOpenBao(t *testing.T) {
	setupOpenBaoTLS(t)

	if err := GenCert(); err != nil {
		t.Fatalf("GenCert failed: %v", err)
	}
	orig, err := os.ReadFile(config.CertFile)
	if err != nil {
		t.Fatalf("failed to read original cert: %v", err)
	}

	if err := GenCert(); err != nil {
		t.Fatalf("GenCert second call failed: %v", err)
	}
	again, err := os.ReadFile(config.CertFile)
	if err != nil {
		t.Fatalf("failed to read cert after second call: %v", err)
	}
	if !bytes.Equal(orig, again) {
		t.Fatal("GenCert should be idempotent when a cert and key already exist — it should not call OpenBao again")
	}
}

func TestGenCertDNSOnlyOpenBao(t *testing.T) {
	setupOpenBaoTLS(t)
	config.CertHosts = []string{"example.com", "foo.example.com"}

	if err := GenCert(); err != nil {
		t.Fatalf("GenCert failed: %v", err)
	}
	certBytes, err := os.ReadFile(config.CertFile)
	if err != nil {
		t.Fatalf("failed to read cert: %v", err)
	}
	block, _ := pem.Decode(certBytes)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse cert: %v", err)
	}
	if len(cert.IPAddresses) != 0 {
		t.Fatalf("expected no IP SANs for DNS-only hosts, got %v", cert.IPAddresses)
	}
	if len(cert.DNSNames) != 2 {
		t.Fatalf("expected 2 DNS SANs, got %d: %v", len(cert.DNSNames), cert.DNSNames)
	}
}

func TestGenCertIPOnlyOpenBao(t *testing.T) {
	setupOpenBaoTLS(t)
	config.CertHosts = []string{"10.0.0.1", "10.0.0.2"}

	if err := GenCert(); err != nil {
		t.Fatalf("GenCert failed: %v", err)
	}
	certBytes, err := os.ReadFile(config.CertFile)
	if err != nil {
		t.Fatalf("failed to read cert: %v", err)
	}
	block, _ := pem.Decode(certBytes)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse cert: %v", err)
	}
	if len(cert.DNSNames) != 0 {
		t.Fatalf("expected no DNS SANs for IP-only hosts, got %v", cert.DNSNames)
	}
	if len(cert.IPAddresses) != 2 {
		t.Fatalf("expected 2 IP SANs, got %d: %v", len(cert.IPAddresses), cert.IPAddresses)
	}
}

func TestGenCertEmptyHostsOpenBao(t *testing.T) {
	setupOpenBaoTLS(t)
	config.CertHosts = []string{}

	if err := GenCert(); err != nil {
		t.Fatalf("GenCert failed: %v", err)
	}
	certBytes, err := os.ReadFile(config.CertFile)
	if err != nil {
		t.Fatalf("failed to read cert: %v", err)
	}
	block, _ := pem.Decode(certBytes)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse cert: %v", err)
	}
	if len(cert.DNSNames) != 0 {
		t.Fatalf("expected no DNS SANs, got %v", cert.DNSNames)
	}
	if len(cert.IPAddresses) != 0 {
		t.Fatalf("expected no IP SANs, got %v", cert.IPAddresses)
	}
}

func TestRotateTLSCertsNoRotationNeededOpenBao(t *testing.T) {
	setupOpenBaoTLS(t)
	config.CertHosts = []string{"localhost"}
	config.CertificateValidTime = 1 * time.Hour

	if err := GenCert(); err != nil {
		t.Fatalf("GenCert failed: %v", err)
	}
	orig, err := os.ReadFile(config.CertFile)
	if err != nil {
		t.Fatalf("failed to read cert: %v", err)
	}

	rotated, err := RotateTLSCerts(1 * time.Minute)
	if err != nil {
		t.Fatalf("RotateTLSCerts error: %v", err)
	}
	if rotated {
		t.Fatal("expected no rotation when the cert is still well within its validity window")
	}
	again, err := os.ReadFile(config.CertFile)
	if err != nil {
		t.Fatalf("failed to read cert after rotation check: %v", err)
	}
	if !bytes.Equal(orig, again) {
		t.Fatal("cert should not have changed")
	}
}

func TestRotateTLSCertsReissuesWhenDueOpenBao(t *testing.T) {
	setupOpenBaoTLS(t)
	config.CertHosts = []string{"localhost"}
	// Short-lived cert so it's immediately within any sane rotation threshold.
	config.CertificateValidTime = 30 * time.Second

	if err := GenCert(); err != nil {
		t.Fatalf("GenCert failed: %v", err)
	}
	orig, err := os.ReadFile(config.CertFile)
	if err != nil {
		t.Fatalf("failed to read cert: %v", err)
	}

	// Threshold far exceeds the cert's ~30s validity, so rotation is due.
	// OpenBao's PKI engine reports the resulting lease as non-renewable
	// (verified against a live dev server), so this exercises the
	// renew-fails-then-reissue path end to end against real OpenBao.
	rotated, err := RotateTLSCerts(1 * time.Hour)
	if err != nil {
		t.Fatalf("RotateTLSCerts error: %v", err)
	}
	if !rotated {
		t.Fatal("expected rotation when the cert is due to expire")
	}
	again, err := os.ReadFile(config.CertFile)
	if err != nil {
		t.Fatalf("failed to read cert after rotation: %v", err)
	}
	if bytes.Equal(orig, again) {
		t.Fatal("cert should have changed after rotation")
	}

	block, _ := pem.Decode(again)
	if block == nil {
		t.Fatal("new cert should be valid PEM")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		t.Fatalf("new cert should be parseable: %v", err)
	}
}

func TestRotateTLSCertsMissingCertOpenBao(t *testing.T) {
	setupOpenBaoTLS(t)
	config.CertHosts = []string{"localhost"}

	rotated, err := RotateTLSCerts(1 * time.Hour)
	if err != nil {
		t.Fatalf("RotateTLSCerts error: %v", err)
	}
	if !rotated {
		t.Fatal("expected rotation when cert doesn't exist")
	}
	if _, err := os.Stat(config.CertFile); err != nil {
		t.Fatalf("cert file should exist after rotation: %v", err)
	}
}

func TestRotateTLSCertsCorruptPEMOpenBao(t *testing.T) {
	setupOpenBaoTLS(t)
	config.CertHosts = []string{"localhost"}

	if err := os.WriteFile(config.CertFile, []byte("not a pem"), 0o644); err != nil {
		t.Fatalf("failed to write corrupt cert: %v", err)
	}

	rotated, err := RotateTLSCerts(1 * time.Hour)
	if err != nil {
		t.Fatalf("RotateTLSCerts error: %v", err)
	}
	if !rotated {
		t.Fatal("expected rotation when cert PEM is corrupt")
	}
	certBytes, err := os.ReadFile(config.CertFile)
	if err != nil {
		t.Fatalf("failed to read cert: %v", err)
	}
	if block, _ := pem.Decode(certBytes); block == nil {
		t.Fatal("new cert should be valid PEM")
	}
}

func TestRotateTLSCertsInvalidDEROpenBao(t *testing.T) {
	setupOpenBaoTLS(t)
	config.CertHosts = []string{"localhost"}

	badPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not valid DER")})
	if err := os.WriteFile(config.CertFile, badPEM, 0o644); err != nil {
		t.Fatalf("failed to write bad cert: %v", err)
	}

	rotated, err := RotateTLSCerts(1 * time.Hour)
	if err != nil {
		t.Fatalf("RotateTLSCerts error: %v", err)
	}
	if !rotated {
		t.Fatal("expected rotation when cert DER is invalid")
	}
}

// TestRotateTLSCertsReadError doesn't need a live OpenBao server: the
// failure happens before any OpenBao call is made.
func TestRotateTLSCertsReadError(t *testing.T) {
	setupTLSConfigDir(t)

	if err := os.MkdirAll(config.CertFile, 0o755); err != nil {
		t.Fatalf("failed to create dir as CertFile: %v", err)
	}

	_, err := RotateTLSCerts(1 * time.Hour)
	if err == nil {
		t.Fatal("expected error when cert file cannot be read")
	}
}

func TestGenCertNotConfigured(t *testing.T) {
	setupTLSConfigDir(t)
	t.Setenv(EnvOpenBaoAddr, "")
	t.Setenv(EnvOpenBaoToken, "")
	t.Setenv(EnvOpenBaoRole, "")

	err := GenCert()
	if !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("expected ErrNotConfigured, got %v", err)
	}
}

// --- Unit tests against a fake OpenBao HTTP server ---------------------
//
// These don't need a real dev server: they exercise error handling and
// the lease-renewal decision in RotateTLSCerts directly against a
// httptest fake, including the "OpenBao successfully renews the lease"
// branch that a stock PKI role (see TestRotateTLSCertsReissuesWhenDueOpenBao)
// never actually takes.

func generateFixtureCAPEM(t *testing.T) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate fixture CA key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"grlx-test-fixture"}},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create fixture CA cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func generateFixtureLeafPEM(t *testing.T, validFor time.Duration) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate fixture leaf key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(validFor),
		DNSNames:              []string{"localhost"},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create fixture leaf cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func issueResponseFixtureJSON(t *testing.T, certPEM, keyPEM, leaseID string) []byte {
	t.Helper()
	resp := issueResponse{
		LeaseID:       leaseID,
		LeaseDuration: 3600,
		Data:          issueData{Certificate: certPEM, PrivateKey: keyPEM},
	}
	b, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal fixture issue response: %v", err)
	}
	return b
}

func TestGenCertCAFetchFails(t *testing.T) {
	dir := setupTLSConfigDir(t)
	_ = dir

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/pki/ca/pem", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	t.Setenv(EnvOpenBaoAddr, srv.URL)
	t.Setenv(EnvOpenBaoToken, "test-token")
	t.Setenv(EnvOpenBaoPKIMount, "pki")
	t.Setenv(EnvOpenBaoRole, "test-role")

	err := GenCert()
	if !errors.Is(err, ErrCAFetchFailed) {
		t.Fatalf("expected ErrCAFetchFailed, got %v", err)
	}
}

func TestGenCertIssueFails(t *testing.T) {
	setupTLSConfigDir(t)
	fixtureCA := generateFixtureCAPEM(t)

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/pki/ca/pem", func(w http.ResponseWriter, r *http.Request) {
		w.Write(fixtureCA)
	})
	mux.HandleFunc("/v1/pki/issue/test-role", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"errors":["boom"]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	t.Setenv(EnvOpenBaoAddr, srv.URL)
	t.Setenv(EnvOpenBaoToken, "test-token")
	t.Setenv(EnvOpenBaoPKIMount, "pki")
	t.Setenv(EnvOpenBaoRole, "test-role")

	err := GenCert()
	if !errors.Is(err, ErrIssueFailed) {
		t.Fatalf("expected ErrIssueFailed, got %v", err)
	}
}

func TestGenCertCertFileUnwritable(t *testing.T) {
	dir := setupTLSConfigDir(t)
	fixtureCA := generateFixtureCAPEM(t)

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/pki/ca/pem", func(w http.ResponseWriter, r *http.Request) {
		w.Write(fixtureCA)
	})
	mux.HandleFunc("/v1/pki/issue/test-role", func(w http.ResponseWriter, r *http.Request) {
		w.Write(issueResponseFixtureJSON(t, "CERTDATA", "KEYDATA", "lease-1"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	readonlyDir := filepath.Join(dir, "readonly")
	if err := os.MkdirAll(readonlyDir, 0o755); err != nil {
		t.Fatalf("failed to create dir: %v", err)
	}
	config.CertFile = filepath.Join(readonlyDir, "cert.pem")
	if err := os.Chmod(readonlyDir, 0o555); err != nil {
		t.Fatalf("failed to chmod: %v", err)
	}
	defer os.Chmod(readonlyDir, 0o755)

	t.Setenv(EnvOpenBaoAddr, srv.URL)
	t.Setenv(EnvOpenBaoToken, "test-token")
	t.Setenv(EnvOpenBaoPKIMount, "pki")
	t.Setenv(EnvOpenBaoRole, "test-role")

	if err := GenCert(); err == nil {
		t.Fatal("GenCert should fail when the cert file cannot be written")
	}
}

func TestGenCertKeyFileUnwritable(t *testing.T) {
	dir := setupTLSConfigDir(t)
	fixtureCA := generateFixtureCAPEM(t)

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/pki/ca/pem", func(w http.ResponseWriter, r *http.Request) {
		w.Write(fixtureCA)
	})
	mux.HandleFunc("/v1/pki/issue/test-role", func(w http.ResponseWriter, r *http.Request) {
		w.Write(issueResponseFixtureJSON(t, "CERTDATA", "KEYDATA", "lease-1"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	readonlyDir := filepath.Join(dir, "readonly")
	if err := os.MkdirAll(readonlyDir, 0o755); err != nil {
		t.Fatalf("failed to create dir: %v", err)
	}
	config.KeyFile = filepath.Join(readonlyDir, "key.pem")
	if err := os.Chmod(readonlyDir, 0o555); err != nil {
		t.Fatalf("failed to chmod: %v", err)
	}
	defer os.Chmod(readonlyDir, 0o755)

	t.Setenv(EnvOpenBaoAddr, srv.URL)
	t.Setenv(EnvOpenBaoToken, "test-token")
	t.Setenv(EnvOpenBaoPKIMount, "pki")
	t.Setenv(EnvOpenBaoRole, "test-role")

	if err := GenCert(); err == nil {
		t.Fatal("GenCert should fail when the key file cannot be written")
	}
}

func TestRotateTLSCertsLeaseRenewedSkipsReissue(t *testing.T) {
	setupTLSConfigDir(t)
	config.CertHosts = []string{"localhost"}
	config.CertificateValidTime = time.Hour

	// Seed a near-expiry "current" certificate. RotateTLSCerts only needs
	// to parse it for NotAfter here; the renewal decision happens before
	// any reissue (and thus before any chain-of-trust check) would occur.
	certPEM := generateFixtureLeafPEM(t, 30*time.Second)
	if err := os.WriteFile(config.CertFile, certPEM, 0o644); err != nil {
		t.Fatalf("failed to write fixture cert: %v", err)
	}
	if err := os.WriteFile(config.KeyFile, []byte("dummy"), 0o600); err != nil {
		t.Fatalf("failed to write fixture key: %v", err)
	}

	renewCalled := false
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/sys/leases/renew", func(w http.ResponseWriter, r *http.Request) {
		renewCalled = true
		w.Write([]byte(`{"lease_id":"pki/issue/test-role/abc","lease_duration":7200,"renewable":true}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	t.Setenv(EnvOpenBaoAddr, srv.URL)
	t.Setenv(EnvOpenBaoToken, "test-token")
	t.Setenv(EnvOpenBaoPKIMount, "pki")
	t.Setenv(EnvOpenBaoRole, "test-role")

	rememberLease("pki/issue/test-role/abc")
	t.Cleanup(func() { rememberLease("") })

	// Threshold (1h) far exceeds the fixture cert's ~30s remaining
	// validity, so rotation is due; OpenBao's fake renewal response grants
	// far more than the threshold, so no reissue should happen.
	rotated, err := RotateTLSCerts(1 * time.Hour)
	if err != nil {
		t.Fatalf("RotateTLSCerts error: %v", err)
	}
	if rotated {
		t.Fatal("expected no rotation when OpenBao renews the lease past the threshold")
	}
	if !renewCalled {
		t.Fatal("expected RotateTLSCerts to attempt an OpenBao lease renewal")
	}
	after, err := os.ReadFile(config.CertFile)
	if err != nil {
		t.Fatalf("failed to read cert: %v", err)
	}
	if !bytes.Equal(after, certPEM) {
		t.Fatal("cert should not have been rewritten when the lease was successfully renewed")
	}
}

func TestRotateTLSCertsLeaseRenewalFailsReissues(t *testing.T) {
	setupTLSConfigDir(t)
	config.CertHosts = []string{"localhost"}
	config.CertificateValidTime = time.Hour

	certPEM := generateFixtureLeafPEM(t, 30*time.Second)
	if err := os.WriteFile(config.CertFile, certPEM, 0o644); err != nil {
		t.Fatalf("failed to write fixture cert: %v", err)
	}
	if err := os.WriteFile(config.KeyFile, []byte("dummy"), 0o600); err != nil {
		t.Fatalf("failed to write fixture key: %v", err)
	}

	fixtureCA := generateFixtureCAPEM(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/sys/leases/renew", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"errors":["lease is not renewable"]}`))
	})
	mux.HandleFunc("/v1/pki/ca/pem", func(w http.ResponseWriter, r *http.Request) {
		w.Write(fixtureCA)
	})
	mux.HandleFunc("/v1/pki/issue/test-role", func(w http.ResponseWriter, r *http.Request) {
		w.Write(issueResponseFixtureJSON(t, "NEWCERTPEM", "NEWKEYPEM", "lease-2"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	t.Setenv(EnvOpenBaoAddr, srv.URL)
	t.Setenv(EnvOpenBaoToken, "test-token")
	t.Setenv(EnvOpenBaoPKIMount, "pki")
	t.Setenv(EnvOpenBaoRole, "test-role")

	rememberLease("pki/issue/test-role/abc")
	t.Cleanup(func() { rememberLease("") })

	rotated, err := RotateTLSCerts(1 * time.Hour)
	if err != nil {
		t.Fatalf("RotateTLSCerts error: %v", err)
	}
	if !rotated {
		t.Fatal("expected reissue when OpenBao reports the lease can't be renewed")
	}
	newCert, err := os.ReadFile(config.CertFile)
	if err != nil {
		t.Fatalf("failed to read cert: %v", err)
	}
	if string(newCert) != "NEWCERTPEM" {
		t.Fatalf("expected reissued certificate content, got %q", string(newCert))
	}
}

// --- NKey tests (unrelated to OpenBao; unchanged) -----------------------

func TestGenNKeyFarmer(t *testing.T) {
	setupNKeyConfigDir(t)

	if err := GenNKey(true); err != nil {
		t.Fatalf("GenNKey(true) failed: %v", err)
	}

	// Verify pub key file was created
	pubBytes, err := os.ReadFile(config.NKeyFarmerPubFile)
	if err != nil {
		t.Fatalf("failed to read farmer pub key: %v", err)
	}
	if len(pubBytes) == 0 {
		t.Fatal("farmer pub key file is empty")
	}
	if pubBytes[0] != 'U' {
		t.Fatalf("expected NATS user public key starting with 'U', got %c", pubBytes[0])
	}

	// Verify priv key file was created
	privBytes, err := os.ReadFile(config.NKeyFarmerPrivFile)
	if err != nil {
		t.Fatalf("failed to read farmer priv key: %v", err)
	}
	if len(privBytes) == 0 {
		t.Fatal("farmer priv key file is empty")
	}
	if privBytes[0] != 'S' {
		t.Fatalf("expected NATS seed starting with 'S', got %c", privBytes[0])
	}

	// Verify file permissions
	info, err := os.Stat(config.NKeyFarmerPrivFile)
	if err != nil {
		t.Fatalf("failed to stat farmer priv key: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected priv key permissions 0600, got %o", info.Mode().Perm())
	}
	info, err = os.Stat(config.NKeyFarmerPubFile)
	if err != nil {
		t.Fatalf("failed to stat farmer pub key: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected pub key permissions 0600, got %o", info.Mode().Perm())
	}
}

func TestGenNKeySprout(t *testing.T) {
	setupNKeyConfigDir(t)

	if err := GenNKey(false); err != nil {
		t.Fatalf("GenNKey(false) failed: %v", err)
	}

	pubBytes, err := os.ReadFile(config.NKeySproutPubFile)
	if err != nil {
		t.Fatalf("failed to read sprout pub key: %v", err)
	}
	if len(pubBytes) == 0 {
		t.Fatal("sprout pub key file is empty")
	}
	if pubBytes[0] != 'U' {
		t.Fatalf("expected NATS user public key starting with 'U', got %c", pubBytes[0])
	}

	privBytes, err := os.ReadFile(config.NKeySproutPrivFile)
	if err != nil {
		t.Fatalf("failed to read sprout priv key: %v", err)
	}
	if len(privBytes) == 0 {
		t.Fatal("sprout priv key file is empty")
	}
}

func TestGenNKeyIdempotent(t *testing.T) {
	setupNKeyConfigDir(t)

	if err := GenNKey(true); err != nil {
		t.Fatalf("GenNKey(true) failed: %v", err)
	}

	origPub, err := os.ReadFile(config.NKeyFarmerPubFile)
	if err != nil {
		t.Fatalf("failed to read original pub key: %v", err)
	}

	// Call again — should not regenerate
	if err := GenNKey(true); err != nil {
		t.Fatalf("GenNKey(true) second call failed: %v", err)
	}

	newPub, err := os.ReadFile(config.NKeyFarmerPubFile)
	if err != nil {
		t.Fatalf("failed to read pub key after second call: %v", err)
	}
	if string(origPub) != string(newPub) {
		t.Fatal("GenNKey should be idempotent — key changed on second call")
	}
}

func TestGenNKeyFarmerAndSproutDistinct(t *testing.T) {
	setupNKeyConfigDir(t)

	if err := GenNKey(true); err != nil {
		t.Fatalf("GenNKey(true) failed: %v", err)
	}
	if err := GenNKey(false); err != nil {
		t.Fatalf("GenNKey(false) failed: %v", err)
	}

	farmerPub, err := os.ReadFile(config.NKeyFarmerPubFile)
	if err != nil {
		t.Fatalf("failed to read farmer pub key: %v", err)
	}
	sproutPub, err := os.ReadFile(config.NKeySproutPubFile)
	if err != nil {
		t.Fatalf("failed to read sprout pub key: %v", err)
	}
	if string(farmerPub) == string(sproutPub) {
		t.Fatal("farmer and sprout NKeys should be distinct")
	}
}

func TestGenNKeyUnwritablePubDir(t *testing.T) {
	dir := t.TempDir()
	readonlyDir := filepath.Join(dir, "readonly")
	if err := os.MkdirAll(readonlyDir, 0o755); err != nil {
		t.Fatalf("failed to create dir: %v", err)
	}
	// Use 0o555 so stat works but write fails.
	if err := os.Chmod(readonlyDir, 0o555); err != nil {
		t.Fatalf("failed to chmod: %v", err)
	}
	defer os.Chmod(readonlyDir, 0o755)

	config.NKeyFarmerPrivFile = filepath.Join(readonlyDir, "farmer.nkey")
	config.NKeyFarmerPubFile = filepath.Join(readonlyDir, "farmer.pub")

	err := GenNKey(true)
	if err == nil {
		t.Fatal("GenNKey should fail when pub key directory is not writable")
	}
}

func TestGenNKeyUnwritablePrivDir(t *testing.T) {
	dir := t.TempDir()
	writableDir := t.TempDir()
	readonlyDir := filepath.Join(dir, "readonly")
	if err := os.MkdirAll(readonlyDir, 0o755); err != nil {
		t.Fatalf("failed to create dir: %v", err)
	}

	// Pub goes to writable dir, priv to read-only dir
	config.NKeyFarmerPubFile = filepath.Join(writableDir, "farmer.pub")
	config.NKeyFarmerPrivFile = filepath.Join(readonlyDir, "farmer.nkey")

	if err := os.Chmod(readonlyDir, 0o555); err != nil {
		t.Fatalf("failed to chmod: %v", err)
	}
	defer os.Chmod(readonlyDir, 0o755)

	err := GenNKey(true)
	if err == nil {
		t.Fatal("GenNKey should fail when priv key directory is not writable")
	}
}

func TestGetPubNKeyFarmer(t *testing.T) {
	setupNKeyConfigDir(t)

	if err := GenNKey(true); err != nil {
		t.Fatalf("GenNKey(true) failed: %v", err)
	}

	pubKey, err := GetPubNKey(true)
	if err != nil {
		t.Fatalf("GetPubNKey(true) failed: %v", err)
	}
	if len(pubKey) == 0 {
		t.Fatal("GetPubNKey returned empty string")
	}
	if pubKey[0] != 'U' {
		t.Fatalf("expected NATS user public key starting with 'U', got %c", pubKey[0])
	}
}

func TestGetPubNKeySprout(t *testing.T) {
	setupNKeyConfigDir(t)

	if err := GenNKey(false); err != nil {
		t.Fatalf("GenNKey(false) failed: %v", err)
	}

	pubKey, err := GetPubNKey(false)
	if err != nil {
		t.Fatalf("GetPubNKey(false) failed: %v", err)
	}
	if len(pubKey) == 0 {
		t.Fatal("GetPubNKey returned empty string")
	}
}

func TestGetPubNKeyMissing(t *testing.T) {
	setupNKeyConfigDir(t)

	_, err := GetPubNKey(true)
	if err == nil {
		t.Fatal("GetPubNKey should fail when key file doesn't exist")
	}
}

func TestGenNKeySeedData(t *testing.T) {
	setupNKeyConfigDir(t)

	if err := GenNKey(true); err != nil {
		t.Fatalf("GenNKey(true) failed: %v", err)
	}

	privBytes, err := os.ReadFile(config.NKeyFarmerPrivFile)
	if err != nil {
		t.Fatalf("failed to read priv key: %v", err)
	}
	if len(privBytes) < 4 {
		t.Fatal("private key seed too short")
	}
	if privBytes[0] != 'S' {
		t.Fatalf("expected seed starting with S, got %c", privBytes[0])
	}
	if privBytes[1] != 'U' {
		t.Fatalf("expected user seed (SU...), got S%c", privBytes[1])
	}
}

func TestGenNKeyStatErrorNotENOENT(t *testing.T) {
	// Cover the branch: os.Stat returns an error that is NOT os.IsNotExist.
	// This happens when the parent directory has no execute permission (EACCES).
	dir := t.TempDir()
	noExecDir := filepath.Join(dir, "noexec")
	if err := os.MkdirAll(noExecDir, 0o755); err != nil {
		t.Fatalf("failed to create dir: %v", err)
	}

	config.NKeyFarmerPrivFile = filepath.Join(noExecDir, "subdir", "farmer.nkey")
	config.NKeyFarmerPubFile = filepath.Join(dir, "farmer.pub")

	// Remove execute permission from noExecDir — os.Stat on the nested path
	// returns EACCES (not ENOENT).
	if err := os.Chmod(noExecDir, 0o600); err != nil {
		t.Fatalf("failed to chmod: %v", err)
	}
	defer os.Chmod(noExecDir, 0o755)

	err := GenNKey(true)
	if err == nil {
		t.Fatal("GenNKey should fail when stat returns non-ENOENT error")
	}
}

func TestGenNKeyWritePubFails(t *testing.T) {
	// Cover GenNKey error when pub key write fails but stat returns ENOENT.
	// Dir has read+execute (so stat can see file doesn't exist) but no write.
	dir := t.TempDir()
	noWriteDir := filepath.Join(dir, "nowrite")
	if err := os.MkdirAll(noWriteDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// Priv file in writable dir so stat returns ENOENT.
	config.NKeyFarmerPrivFile = filepath.Join(dir, "farmer.nkey")
	// Pub file in read-only dir so write fails.
	config.NKeyFarmerPubFile = filepath.Join(noWriteDir, "farmer.pub")

	if err := os.Chmod(noWriteDir, 0o555); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	defer os.Chmod(noWriteDir, 0o755)

	err := GenNKey(true)
	if err == nil {
		t.Fatal("GenNKey should fail when pub key write fails")
	}
}

func TestGenNKeyWritePrivFails(t *testing.T) {
	// Cover GenNKey error when priv key write fails after pub succeeds.
	// Both are in different dirs: priv dir is read-only, pub dir is writable.
	dir := t.TempDir()
	noWriteDir := filepath.Join(dir, "nowrite")
	if err := os.MkdirAll(noWriteDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// Priv file in read-only dir — stat returns ENOENT (file doesn't exist,
	// but dir is readable so stat can check).
	config.NKeyFarmerPrivFile = filepath.Join(noWriteDir, "farmer.nkey")
	// Pub file in writable dir — write succeeds.
	config.NKeyFarmerPubFile = filepath.Join(dir, "farmer.pub")

	if err := os.Chmod(noWriteDir, 0o555); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	defer os.Chmod(noWriteDir, 0o755)

	err := GenNKey(true)
	if err == nil {
		t.Fatal("GenNKey should fail when priv key write fails")
	}
}
