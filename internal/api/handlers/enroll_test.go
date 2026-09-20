package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gogrlx/grlx/v2/internal/config"
	"github.com/gogrlx/grlx/v2/internal/pki"
)

func TestEnroll_InvalidJSON(t *testing.T) {
	setupPKIDirs(t)

	req := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader([]byte("not json")))
	w := httptest.NewRecorder()
	Enroll(w, req)

	assertEnrollFailed(t, w)
}

func TestEnroll_MissingFields(t *testing.T) {
	setupPKIDirs(t)

	body, _ := json.Marshal(enrollRequest{JoinToken: "ek_1.secret", NKeyPub: "", Hostname: "web-01"})
	req := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(body))
	w := httptest.NewRecorder()
	Enroll(w, req)

	assertEnrollFailed(t, w)
}

func TestEnroll_UnknownToken(t *testing.T) {
	setupPKIDirs(t)

	nkey := generateTestUserNKey(t)
	body, _ := json.Marshal(enrollRequest{JoinToken: "ek_nope.secret", NKeyPub: nkey, Hostname: "web-01"})
	req := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(body))
	w := httptest.NewRecorder()
	Enroll(w, req)

	// No saas.enrollment_keys table exists against this test's SQLite db,
	// so this exercises pki.Enroll's generic-failure path exactly like a
	// real unknown key_id would — same response either way (design §3.4).
	assertEnrollFailed(t, w)
}

// TestEnroll_IdempotentReplaySucceeds drives a full 200 response through
// the handler without needing a real saas.enrollment_keys table: an
// already-accepted nkey_pub takes design doc §3.3 step 1's idempotency
// path, which never touches the enrollment-key store at all.
func TestEnroll_IdempotentReplaySucceeds(t *testing.T) {
	setupPKIDirs(t)
	config.FarmerWSPort = "5407"

	nkey := generateTestUserNKey(t)
	if err := pki.UnacceptNKey("web-01", nkey); err != nil {
		t.Fatalf("UnacceptNKey: %v", err)
	}
	if err := pki.AcceptNKey("web-01"); err != nil {
		t.Fatalf("AcceptNKey: %v", err)
	}

	body, _ := json.Marshal(enrollRequest{JoinToken: "irrelevant.token", NKeyPub: nkey, Hostname: "web-01"})
	req := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(body))
	w := httptest.NewRecorder()
	Enroll(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp enrollSuccessResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if resp.SproutID != "web-01" {
		t.Errorf("expected sprout_id web-01, got %q", resp.SproutID)
	}
	if resp.JWT == "" {
		t.Error("expected non-empty jwt")
	}
	if resp.NKeyIdentity != nkey {
		t.Errorf("expected nkey_identity %q, got %q", nkey, resp.NKeyIdentity)
	}
	if resp.TenantX25519Pub == "" {
		t.Error("expected non-empty tenant_x25519_pub")
	}
	wantURL := "wss://127.0.0.1:5407"
	if len(resp.NatsURLs) != 1 || resp.NatsURLs[0] != wantURL {
		t.Errorf("expected nats_urls [%q], got %v", wantURL, resp.NatsURLs)
	}
}

func assertEnrollFailed(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
	var resp enrollErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding error response: %v", err)
	}
	if resp.Error != "enrollment_failed" {
		t.Errorf("expected generic enrollment_failed error, got %q", resp.Error)
	}
}
