package fleetsign

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

// mockTransit serves Transit's GET <mount>/keys/<key> in the documented
// response shape, the same stand-in approach as internal/gatewayjwt's
// mockTransitServer (no real OpenBao is reachable in unit tests; see
// cmd/fleetreleaser's env-gated TestOpenBaoEnforcesReadOnlyFleetKey for
// the real-server check). Any other path is a 404, so a stray request
// from this read-only client would fail the test.
type mockTransit struct {
	token         string
	keys          []PublicKey
	minEncryption int
	keyType       string
	reads         atomic.Int32
	otherRequests atomic.Int32
}

func (m *mockTransit) start(t *testing.T) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/transit/keys/"+DefaultTransitKeyName {
			m.otherRequests.Add(1)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Header.Get("X-Vault-Token") != m.token {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]any{"errors": []string{"permission denied"}})
			return
		}
		m.reads.Add(1)
		keys := map[string]any{}
		for _, k := range m.keys {
			der, _ := x509.MarshalPKIXPublicKey(k.Key)
			keys[strconv.Itoa(k.Version)] = map[string]any{
				"public_key": string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})),
			}
		}
		keyType := m.keyType
		if keyType == "" {
			keyType = "ed25519"
		}
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"type": keyType, "keys": keys, "min_encryption_version": m.minEncryption, "latest_version": len(m.keys),
		}})
	}))
	t.Cleanup(ts.Close)
	t.Setenv(EnvOpenBaoAddr, ts.URL)
	t.Setenv(EnvOpenBaoTransitMount, "")
	t.Setenv(EnvOpenBaoAuthMethod, AuthMethodToken)
	t.Setenv(EnvOpenBaoToken, m.token)
	t.Setenv(EnvTransitKeyName, "")
	return ts
}

func TestTransitKeySource_ReadsAndCaches(t *testing.T) {
	k1, priv1 := newTestKey(t, 1)
	k2, _ := newTestKey(t, 2)
	m := &mockTransit{token: "ro-token", keys: []PublicKey{k1, k2}}
	m.start(t)

	src, err := NewTransitKeySourceFromEnv()
	if err != nil {
		t.Fatalf("NewTransitKeySourceFromEnv: %v", err)
	}
	ks, err := src.KeySet(t.Context())
	if err != nil {
		t.Fatalf("KeySet: %v", err)
	}
	if len(ks) != 2 || !ks[0].Key.Equal(k1.Key) || !ks[1].Key.Equal(k2.Key) {
		t.Fatalf("KeySet = %+v", ks)
	}
	if err := src.Verify(t.Context(), testRelease(), signForTest(t, priv1, 1, testRelease())); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got := m.reads.Load(); got != 1 {
		t.Errorf("Transit reads = %d, want 1 (second call cached)", got)
	}
	if got := m.otherRequests.Load(); got != 0 {
		t.Errorf("client made %d requests other than a key read", got)
	}
}

// min_encryption_version is the floor, copied from gatewayjwt's
// PublicKeys: raising it retires the versions below it for verification.
func TestTransitKeySource_HonorsMinEncryptionVersion(t *testing.T) {
	k1, priv1 := newTestKey(t, 1)
	k2, _ := newTestKey(t, 2)
	m := &mockTransit{token: "ro-token", keys: []PublicKey{k1, k2}, minEncryption: 2}
	m.start(t)
	src, _ := NewTransitKeySourceFromEnv()
	err := src.Verify(t.Context(), testRelease(), signForTest(t, priv1, 1, testRelease()))
	if !errors.Is(err, ErrUnknownKeyVersion) {
		t.Fatalf("Verify with retired v1 = %v, want ErrUnknownKeyVersion", err)
	}
}

func TestTransitKeySource_Failures(t *testing.T) {
	k1, _ := newTestKey(t, 1)

	m := &mockTransit{token: "right", keys: []PublicKey{k1}}
	m.start(t)
	t.Setenv(EnvOpenBaoToken, "wrong")
	src, _ := NewTransitKeySourceFromEnv()
	if _, err := src.KeySet(t.Context()); !errors.Is(err, ErrReadKeyFailed) {
		t.Errorf("wrong token: %v, want ErrReadKeyFailed", err)
	}

	m2 := &mockTransit{token: "t", keys: []PublicKey{k1}, keyType: "aes256-gcm96"}
	m2.start(t)
	src2, _ := NewTransitKeySourceFromEnv()
	if _, err := src2.KeySet(t.Context()); !errors.Is(err, ErrReadKeyFailed) {
		t.Errorf("non-ed25519 key: %v, want ErrReadKeyFailed", err)
	}
}

func TestNewTransitKeySourceFromEnv_NotConfigured(t *testing.T) {
	t.Setenv(EnvOpenBaoAddr, "")
	if _, err := NewTransitKeySourceFromEnv(); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("missing addr: %v", err)
	}
	t.Setenv(EnvOpenBaoAddr, "http://127.0.0.1:1")
	t.Setenv(EnvOpenBaoAuthMethod, "")
	t.Setenv(EnvOpenBaoToken, "")
	if _, err := NewTransitKeySourceFromEnv(); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("missing token: %v", err)
	}
	t.Setenv(EnvOpenBaoAuthMethod, "carrier-pigeon")
	if _, err := NewTransitKeySourceFromEnv(); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("unknown auth method: %v", err)
	}
	t.Setenv(EnvOpenBaoAuthMethod, AuthMethodKubernetes)
	t.Setenv(EnvOpenBaoK8sRole, "")
	if _, err := NewTransitKeySourceFromEnv(); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("missing k8s role: %v", err)
	}
}

func TestJWKS_RoundTrip(t *testing.T) {
	k1, _ := newTestKey(t, 1)
	k2, _ := newTestKey(t, 2)
	ks, _ := NewKeySet([]PublicKey{k2, k1})
	data, err := ks.MarshalJWKS()
	if err != nil {
		t.Fatalf("MarshalJWKS: %v", err)
	}
	for _, want := range []string{`"kty":"OKP"`, `"crv":"Ed25519"`, `"kid":"1"`, `"kid":"2"`, `"alg":"EdDSA"`, `"use":"sig"`} {
		if !strings.Contains(string(data), want) {
			t.Errorf("JWKS %s missing %s", data, want)
		}
	}
	back, err := ParseJWKS(data)
	if err != nil {
		t.Fatalf("ParseJWKS: %v", err)
	}
	if len(back) != 2 || !back[0].Key.Equal(k1.Key) || !back[1].Key.Equal(k2.Key) {
		t.Fatalf("ParseJWKS = %+v", back)
	}
}

func TestParseJWKS_Strict(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	x := jwkB64(pub)
	d := jwkB64(priv.Seed())
	cases := map[string]string{
		"not json":       `{`,
		"empty set":      `{"keys":[]}`,
		"private key":    `{"keys":[{"kty":"OKP","crv":"Ed25519","x":"` + x + `","d":"` + d + `","kid":"1"}]}`,
		"no kid":         `{"keys":[{"kty":"OKP","crv":"Ed25519","x":"` + x + `"}]}`,
		"non-numeric":    `{"keys":[{"kty":"OKP","crv":"Ed25519","x":"` + x + `","kid":"gw-2026"}]}`,
		"zero kid":       `{"keys":[{"kty":"OKP","crv":"Ed25519","x":"` + x + `","kid":"0"}]}`,
		"wrong use":      `{"keys":[{"kty":"OKP","crv":"Ed25519","x":"` + x + `","kid":"1","use":"enc"}]}`,
		"wrong alg":      `{"keys":[{"kty":"OKP","crv":"Ed25519","x":"` + x + `","kid":"1","alg":"ES256"}]}`,
		"x25519 not sig": `{"keys":[{"kty":"OKP","crv":"X25519","x":"` + x + `","kid":"1"}]}`,
		"duplicate kid":  `{"keys":[{"kty":"OKP","crv":"Ed25519","x":"` + x + `","kid":"1"},{"kty":"OKP","crv":"Ed25519","x":"` + x + `","kid":"1"}]}`,
	}
	for name, doc := range cases {
		if _, err := ParseJWKS([]byte(doc)); err == nil {
			t.Errorf("%s: ParseJWKS accepted %s", name, doc)
		}
	}
}

func TestJWKSHandler(t *testing.T) {
	k1, _ := newTestKey(t, 1)
	m := &mockTransit{token: "ro-token", keys: []PublicKey{k1}}
	m.start(t)
	src, _ := NewTransitKeySourceFromEnv()

	rec := httptest.NewRecorder()
	JWKSHandler(src)(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("status %d, content-type %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	ks, err := ParseJWKS(rec.Body.Bytes())
	if err != nil || len(ks) != 1 || !ks[0].Key.Equal(k1.Key) {
		t.Fatalf("served JWKS = %s (%v)", rec.Body, err)
	}

	t.Setenv(EnvOpenBaoToken, "wrong")
	bad, _ := NewTransitKeySourceFromEnv()
	rec = httptest.NewRecorder()
	JWKSHandler(bad)(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status with failing Transit = %d, want 503", rec.Code)
	}
}

func jwkB64(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}
