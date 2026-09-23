package saasapi

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestAuth_CurrentSecretValidJWTMatchingTenant_200 is the happy path:
// layer 1's current secret, plus a layer-2 JWT whose organization.id
// matches the {tenant_id} path parameter.
func TestAuth_CurrentSecretValidJWTMatchingTenant_200(t *testing.T) {
	newTestDB(t)
	auth := newTestAuthEnv(t)
	tenantID := mustCreateTenant(t, "Acme Bank")
	mux := NewRouter()

	r := httptest.NewRequest("GET", "/v1/tenants/"+tenantID, nil)
	auth.setAuthHeaders(r, tenantID)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200, body=%s", w.Code, w.Body.String())
	}
}

// TestAuth_PreviousSecretValidJWT_200 covers the rotation window: a
// caller still presenting INTERNAL_AUTH_SECRET_PREVIOUS must succeed
// exactly like one presenting the current value.
func TestAuth_PreviousSecretValidJWT_200(t *testing.T) {
	newTestDB(t)
	auth := newTestAuthEnv(t)
	tenantID := mustCreateTenant(t, "Acme Bank")
	mux := NewRouter()

	r := httptest.NewRequest("GET", "/v1/tenants/"+tenantID, nil)
	r.Header.Set(InternalAuthHeader, testInternalAuthSecretPrevious)
	r.Header.Set("Authorization", "Bearer "+auth.mintTokenForTenant(tenantID))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200, body=%s", w.Code, w.Body.String())
	}
}

// TestAuth_PreviousSecretUnset_NotAcceptedAsCurrent pins that leaving
// INTERNAL_AUTH_SECRET_PREVIOUS unset makes that rotation path simply
// unavailable — not a silent "accept anything" fallback. With no
// previous configured, a caller presenting what would have been the
// previous value must be rejected exactly like any other wrong secret.
func TestAuth_PreviousSecretUnset_NotAcceptedAsCurrent(t *testing.T) {
	newTestDB(t)
	auth := newTestAuthEnvWithSecrets(t, testInternalAuthSecretCurrent, "")
	tenantID := mustCreateTenant(t, "Acme Bank")
	mux := NewRouter()

	r := httptest.NewRequest("GET", "/v1/tenants/"+tenantID, nil)
	r.Header.Set(InternalAuthHeader, testInternalAuthSecretPrevious)
	r.Header.Set("Authorization", "Bearer "+auth.mintTokenForTenant(tenantID))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	if w.Code != 401 {
		t.Fatalf("status = %d, want 401 (no previous secret configured), body=%s", w.Code, w.Body.String())
	}
}

// TestAuth_WrongSharedSecret_401 covers a valid JWT paired with a wrong
// or missing shared secret — layer 1 must reject before layer 2 is ever
// consulted.
func TestAuth_WrongSharedSecret_401(t *testing.T) {
	newTestDB(t)
	auth := newTestAuthEnv(t)
	tenantID := mustCreateTenant(t, "Acme Bank")
	mux := NewRouter()

	cases := []struct {
		name   string
		secret string
	}{
		{"wrong value", "not-the-right-secret"},
		{"missing header", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/v1/tenants/"+tenantID, nil)
			if tc.secret != "" {
				r.Header.Set(InternalAuthHeader, tc.secret)
			}
			r.Header.Set("Authorization", "Bearer "+auth.mintTokenForTenant(tenantID))
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)

			if w.Code != 401 {
				t.Fatalf("status = %d, want 401, body=%s", w.Code, w.Body.String())
			}
		})
	}
}

// TestAuth_OrganizationMismatch_403 covers a valid caller on both layers
// asking for a tenant other than its own.
func TestAuth_OrganizationMismatch_403(t *testing.T) {
	newTestDB(t)
	auth := newTestAuthEnv(t)
	tenantID := mustCreateTenant(t, "Acme Bank")
	mux := NewRouter()

	r := httptest.NewRequest("GET", "/v1/tenants/"+tenantID, nil)
	auth.setAuthHeaders(r, "some-other-tenant-id")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	if w.Code != 403 {
		t.Fatalf("status = %d, want 403, body=%s", w.Code, w.Body.String())
	}
}

// TestAuth_OrganizationClaimMissingOrMalformed_403 covers the
// defensive-safety-net case: an otherwise-valid, otherwise-verified JWT
// whose organization claim is absent or doesn't parse. This must never
// panic, and must warn server-side rather than pass silently — Keycloak
// is expected to always send this claim, so seeing it missing means
// something upstream is broken.
func TestAuth_OrganizationClaimMissingOrMalformed_403(t *testing.T) {
	newTestDB(t)
	auth := newTestAuthEnv(t)
	tenantID := mustCreateTenant(t, "Acme Bank")
	mux := NewRouter()

	cases := []struct {
		name string
		opts tokenOpts
	}{
		{"claim absent", tokenOpts{}},
		{"claim present without id", tokenOpts{badOrg: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withVerboseLogging(t)
			var status int
			output := captureStderr(t, func() {
				r := httptest.NewRequest("GET", "/v1/tenants/"+tenantID, nil)
				r.Header.Set(InternalAuthHeader, testInternalAuthSecretCurrent)
				r.Header.Set("Authorization", "Bearer "+auth.mintToken(tc.opts))
				w := httptest.NewRecorder()
				mux.ServeHTTP(w, r)
				status = w.Code
			})

			if status != 403 {
				t.Fatalf("status = %d, want 403, output=%s", status, output)
			}
			if !strings.Contains(output, "organization") {
				t.Fatalf("expected a server-side warning about the organization claim, got:\n%s", output)
			}
		})
	}
}

// TestAuth_ExpiredToken_401 covers a JWT that fails standard expiry
// validation.
func TestAuth_ExpiredToken_401(t *testing.T) {
	newTestDB(t)
	auth := newTestAuthEnv(t)
	tenantID := mustCreateTenant(t, "Acme Bank")
	mux := NewRouter()

	expired := auth.mintToken(tokenOpts{
		org:       &Organization{ID: tenantID},
		expiresAt: time.Now().Add(-time.Hour),
	})

	r := httptest.NewRequest("GET", "/v1/tenants/"+tenantID, nil)
	r.Header.Set(InternalAuthHeader, testInternalAuthSecretCurrent)
	r.Header.Set("Authorization", "Bearer "+expired)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	if w.Code != 401 {
		t.Fatalf("status = %d, want 401, body=%s", w.Code, w.Body.String())
	}
}

// TestAuth_MalformedAuthorizationHeader_401 covers a missing/malformed
// Authorization header on an otherwise-valid layer-1 request.
func TestAuth_MalformedAuthorizationHeader_401(t *testing.T) {
	newTestDB(t)
	newTestAuthEnv(t)
	tenantID := mustCreateTenant(t, "Acme Bank")
	mux := NewRouter()

	cases := []string{"", "not-a-bearer-token", "Bearer ", "Basic dXNlcjpwYXNz"}
	for _, authz := range cases {
		t.Run(authz, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/v1/tenants/"+tenantID, nil)
			r.Header.Set(InternalAuthHeader, testInternalAuthSecretCurrent)
			if authz != "" {
				r.Header.Set("Authorization", authz)
			}
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)

			if w.Code != 401 {
				t.Fatalf("status = %d, want 401, body=%s", w.Code, w.Body.String())
			}
		})
	}
}

// TestAuth_WrongIssuerOrAudience_401 covers a token that verifies
// cryptographically but whose issuer/audience doesn't match this
// service's configuration.
func TestAuth_WrongIssuerOrAudience_401(t *testing.T) {
	newTestDB(t)
	auth := newTestAuthEnv(t)
	tenantID := mustCreateTenant(t, "Acme Bank")
	mux := NewRouter()

	cases := []struct {
		name string
		opts tokenOpts
	}{
		{"wrong issuer", tokenOpts{org: &Organization{ID: tenantID}, issuer: "https://not-our-keycloak.example/realms/other"}},
		{"wrong audience", tokenOpts{org: &Organization{ID: tenantID}, audience: "some-other-service"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/v1/tenants/"+tenantID, nil)
			r.Header.Set(InternalAuthHeader, testInternalAuthSecretCurrent)
			r.Header.Set("Authorization", "Bearer "+auth.mintToken(tc.opts))
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)

			if w.Code != 401 {
				t.Fatalf("status = %d, want 401, body=%s", w.Code, w.Body.String())
			}
		})
	}
}

// TestAuth_RouteWithoutTenantID_SkipsOrganizationCheck covers §1.8-style
// fleet-catalog routes (and, today, POST /v1/tenants): layer 1 + a
// valid JWT is enough, and a missing/malformed organization claim must
// NOT cause a failure, because no {tenant_id} path parameter means no
// organization check is applied at all.
func TestAuth_RouteWithoutTenantID_SkipsOrganizationCheck(t *testing.T) {
	newTestDB(t)
	auth := newTestAuthEnv(t)
	mux := NewRouter()

	r := httptest.NewRequest("POST", "/v1/tenants", strings.NewReader(`{"name":"Acme Bank","plan_id":"plan_std"}`))
	r.Header.Set(InternalAuthHeader, testInternalAuthSecretCurrent)
	// badOrg: true means the organization claim is malformed. If the
	// check were mistakenly applied to this route, this would 403.
	r.Header.Set("Authorization", "Bearer "+auth.mintToken(tokenOpts{badOrg: true}))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	if w.Code != 202 {
		t.Fatalf("status = %d, want 202, body=%s", w.Code, w.Body.String())
	}
}
