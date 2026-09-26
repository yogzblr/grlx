package http

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeServerCA writes ts's certificate (httptest's self-signed leaf is
// its own root) as a PEM trust root, the way a sprout's tls-rootca.pem
// holds farmer's CA.
func writeServerCA(t *testing.T, ts *httptest.Server) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tls-rootca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw}), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// writeUnrelatedCA writes a freshly generated CA the server's cert does
// not chain to.
func writeUnrelatedCA(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "some other root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "other-rootca.pem")
	os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	return path
}

func pinnedFile(src, dst, caFile string) HTTPFile {
	return HTTPFile{ID: "pinned", Source: src, Destination: dst, Props: map[string]interface{}{PropRootCAFile: caFile}}
}

func TestPinnedRoots_DownloadsWhenChainMatches(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("artifact")) }))
	defer ts.Close()
	dst := filepath.Join(t.TempDir(), "out")
	if err := pinnedFile(ts.URL+"/a", dst, writeServerCA(t, ts)).Download(context.Background()); err != nil {
		t.Fatalf("Download: %v", err)
	}
	if data, _ := os.ReadFile(dst); string(data) != "artifact" {
		t.Fatalf("content = %q", data)
	}
}

// The artifact host's certificate doesn't chain to the pinned root: the
// TLS handshake is refused and nothing is written.
func TestPinnedRoots_RefusesCertNotChainingToPinnedRoot(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("artifact")) }))
	defer ts.Close()
	dst := filepath.Join(t.TempDir(), "out")
	err := pinnedFile(ts.URL+"/a", dst, writeUnrelatedCA(t)).Download(context.Background())
	var unknownAuthority x509.UnknownAuthorityError
	if !errors.As(err, &unknownAuthority) {
		t.Fatalf("Download = %v, want x509.UnknownAuthorityError", err)
	}
	if _, statErr := os.Stat(dst); !os.IsNotExist(statErr) {
		t.Fatal("a file was written after a refused TLS handshake")
	}
}

// The pinned client's trust roots are exactly the pinned file's: never
// nil (which would mean the system pool) and never the system pool plus
// extras.
func TestPinnedRoots_ReplaceSystemPool(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer ts.Close()
	client, err := pinnedFile(ts.URL, "", writeServerCA(t, ts)).client()
	if err != nil {
		t.Fatal(err)
	}
	tr, ok := client.Transport.(*http.Transport)
	if !ok || tr.TLSClientConfig == nil || tr.TLSClientConfig.RootCAs == nil {
		t.Fatal("pinned client falls back to the system CA pool")
	}
	want := x509.NewCertPool()
	want.AddCert(ts.Certificate())
	if !tr.TLSClientConfig.RootCAs.Equal(want) {
		t.Fatal("pinned client's RootCAs is not exactly the pinned root")
	}
	if tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("pinned client skips verification")
	}
	// Unpinned downloads are unchanged.
	if c, _ := (HTTPFile{Source: ts.URL}).client(); c != http.DefaultClient {
		t.Fatal("unpinned download no longer uses http.DefaultClient")
	}
}

func TestPinnedRoots_ConfigurationFailuresFailClosed(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer ts.Close()
	dst := filepath.Join(t.TempDir(), "out")
	empty := filepath.Join(t.TempDir(), "empty.pem")
	os.WriteFile(empty, []byte("no certs here"), 0o644)

	for name, tc := range map[string]struct {
		hf   HTTPFile
		want error
	}{
		"http source":       {pinnedFile(strings.Replace(ts.URL, "https://", "http://", 1), dst, writeServerCA(t, ts)), ErrPinnedRootsRequireHTTPS},
		"missing CA file":   {pinnedFile(ts.URL, dst, filepath.Join(t.TempDir(), "nope.pem")), ErrPinnedRootsUnusable},
		"CA file w/o certs": {pinnedFile(ts.URL, dst, empty), ErrPinnedRootsUnusable},
		"empty CA path":     {pinnedFile(ts.URL, dst, ""), ErrPinnedRootsUnusable},
		"non-string CA":     {HTTPFile{Source: ts.URL, Destination: dst, Props: map[string]interface{}{PropRootCAFile: 7}}, ErrPinnedRootsUnusable},
	} {
		if err := tc.hf.Download(context.Background()); !errors.Is(err, tc.want) {
			t.Errorf("%s: Download = %v, want %v", name, err, tc.want)
		}
	}
}

// A pinned download can't be redirected off TLS.
func TestPinnedRoots_RefusesRedirectToHTTP(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("evil")) }))
	defer plain.Close()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+"/x", http.StatusFound)
	}))
	defer ts.Close()
	dst := filepath.Join(t.TempDir(), "out")
	if err := pinnedFile(ts.URL+"/a", dst, writeServerCA(t, ts)).Download(context.Background()); !errors.Is(err, ErrPinnedRootsRequireHTTPS) {
		t.Fatalf("Download = %v, want ErrPinnedRootsRequireHTTPS", err)
	}
}
