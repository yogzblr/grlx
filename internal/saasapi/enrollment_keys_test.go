package saasapi

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCreateEnrollmentKeyUnknownTenant(t *testing.T) {
	newTestDB(t)
	w := doRequest(t, CreateEnrollmentKey, "POST", "/v1/tenants/nope/enrollment-keys",
		map[string]string{"tenant_id": "nope"}, createEnrollmentKeyRequest{ExpiresInHours: 24, MaxUses: 50})
	if w.Code != 404 {
		t.Fatalf("status = %d, want 404, body=%s", w.Code, w.Body.String())
	}
}

func TestCreateEnrollmentKeyValidation(t *testing.T) {
	newTestDB(t)
	tenantID := mustCreateTenant(t, "Acme Bank")

	cases := []createEnrollmentKeyRequest{
		{ExpiresInHours: 0, MaxUses: 50},
		{ExpiresInHours: maxExpiresInHours + 1, MaxUses: 50},
		{ExpiresInHours: 24, MaxUses: 0},
		{ExpiresInHours: 24, MaxUses: maxMaxUses + 1},
	}
	for _, c := range cases {
		w := doRequest(t, CreateEnrollmentKey, "POST", "/v1/tenants/"+tenantID+"/enrollment-keys",
			map[string]string{"tenant_id": tenantID}, c)
		if w.Code != 400 {
			t.Fatalf("case %+v: status = %d, want 400, body=%s", c, w.Code, w.Body.String())
		}
	}
}

// TestCreateEnrollmentKeyNeverPersistsRawSecret is the security-critical
// assertion for this task: the stored row's key_hash must be the SHA-256
// of the issued secret, the raw secret itself must never be persisted,
// and the two halves of the returned registration_key must match key_id
// and the format from design doc §3.1 ("{key_id}.{secret}").
func TestCreateEnrollmentKeyNeverPersistsRawSecret(t *testing.T) {
	gdb := newTestDB(t)
	tenantID := mustCreateTenant(t, "Acme Bank")

	w := doRequest(t, CreateEnrollmentKey, "POST", "/v1/tenants/"+tenantID+"/enrollment-keys",
		map[string]string{"tenant_id": tenantID}, createEnrollmentKeyRequest{ExpiresInHours: 24, MaxUses: 50})
	if w.Code != 200 {
		t.Fatalf("status = %d, want 200, body=%s", w.Code, w.Body.String())
	}

	var resp createEnrollmentKeyResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}

	parts := strings.SplitN(resp.RegistrationKey, ".", 2)
	if len(parts) != 2 {
		t.Fatalf("registration_key %q is not in key_id.secret form", resp.RegistrationKey)
	}
	keyID, secret := parts[0], parts[1]
	if keyID != resp.KeyID {
		t.Fatalf("registration_key's key_id half = %q, want %q", keyID, resp.KeyID)
	}
	if secret == "" {
		t.Fatalf("expected a non-empty secret half")
	}

	var stored EnrollmentKey
	if err := gdb.First(&stored, "key_id = ?", resp.KeyID).Error; err != nil {
		t.Fatalf("loading stored key: %v", err)
	}
	if stored.KeyHash == secret {
		t.Fatalf("raw secret must never be stored as-is")
	}
	if stored.KeyHash != hashSecret(secret) {
		t.Fatalf("key_hash = %q, want sha256(secret) = %q", stored.KeyHash, hashSecret(secret))
	}

	// The raw response body (as sent over the wire) must not leak
	// key_hash under any field name.
	if strings.Contains(w.Body.String(), stored.KeyHash) {
		t.Fatalf("response body leaked the stored key_hash: %s", w.Body.String())
	}
}

func TestListEnrollmentKeysExcludesHashAndShowsState(t *testing.T) {
	newTestDB(t)
	tenantID := mustCreateTenant(t, "Acme Bank")

	w := doRequest(t, CreateEnrollmentKey, "POST", "/v1/tenants/"+tenantID+"/enrollment-keys",
		map[string]string{"tenant_id": tenantID}, createEnrollmentKeyRequest{ExpiresInHours: 24, MaxUses: 50})
	var created createEnrollmentKeyResponse
	json.Unmarshal(w.Body.Bytes(), &created)

	lw := doRequest(t, ListEnrollmentKeys, "GET", "/v1/tenants/"+tenantID+"/enrollment-keys",
		map[string]string{"tenant_id": tenantID}, nil)
	if lw.Code != 200 {
		t.Fatalf("status = %d, want 200, body=%s", lw.Code, lw.Body.String())
	}
	if strings.Contains(lw.Body.String(), "key_hash") {
		t.Fatalf("list response must never include key_hash: %s", lw.Body.String())
	}

	var listResp struct {
		EnrollmentKeys []enrollmentKeyListItem `json:"enrollment_keys"`
	}
	if err := json.Unmarshal(lw.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("decoding list response: %v", err)
	}
	if len(listResp.EnrollmentKeys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(listResp.EnrollmentKeys))
	}
	if listResp.EnrollmentKeys[0].KeyID != created.KeyID {
		t.Fatalf("key_id = %q, want %q", listResp.EnrollmentKeys[0].KeyID, created.KeyID)
	}
	if listResp.EnrollmentKeys[0].State != "active" {
		t.Fatalf("state = %q, want active", listResp.EnrollmentKeys[0].State)
	}
}

func TestDeleteEnrollmentKeyRevokesAndIsTenantScoped(t *testing.T) {
	newTestDB(t)
	tenantA := mustCreateTenant(t, "Acme Bank")
	tenantB := mustCreateTenant(t, "Other Tenant")

	w := doRequest(t, CreateEnrollmentKey, "POST", "/v1/tenants/"+tenantA+"/enrollment-keys",
		map[string]string{"tenant_id": tenantA}, createEnrollmentKeyRequest{ExpiresInHours: 24, MaxUses: 50})
	var created createEnrollmentKeyResponse
	json.Unmarshal(w.Body.Bytes(), &created)

	// A different tenant may not revoke this key — it must resolve to
	// not-found, per design doc §4's tenant-safety convention.
	wrong := doRequest(t, DeleteEnrollmentKey, "DELETE", "/v1/tenants/"+tenantB+"/enrollment-keys/"+created.KeyID,
		map[string]string{"tenant_id": tenantB, "key_id": created.KeyID}, nil)
	if wrong.Code != 404 {
		t.Fatalf("cross-tenant delete status = %d, want 404, body=%s", wrong.Code, wrong.Body.String())
	}

	ok := doRequest(t, DeleteEnrollmentKey, "DELETE", "/v1/tenants/"+tenantA+"/enrollment-keys/"+created.KeyID,
		map[string]string{"tenant_id": tenantA, "key_id": created.KeyID}, nil)
	if ok.Code != 200 {
		t.Fatalf("delete status = %d, want 200, body=%s", ok.Code, ok.Body.String())
	}

	lw := doRequest(t, ListEnrollmentKeys, "GET", "/v1/tenants/"+tenantA+"/enrollment-keys",
		map[string]string{"tenant_id": tenantA}, nil)
	var listResp struct {
		EnrollmentKeys []enrollmentKeyListItem `json:"enrollment_keys"`
	}
	json.Unmarshal(lw.Body.Bytes(), &listResp)
	if len(listResp.EnrollmentKeys) != 1 || listResp.EnrollmentKeys[0].State != "revoked" {
		t.Fatalf("expected the key to show state=revoked, got %+v", listResp.EnrollmentKeys)
	}
}
