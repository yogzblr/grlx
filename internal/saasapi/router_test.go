package saasapi

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRouterRequiresAuthHeader(t *testing.T) {
	newTestDB(t)
	newTestAuthEnv(t)
	mux := NewRouter()

	r := httptest.NewRequest("GET", "/v1/tenants/t_x", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	if w.Code != 401 {
		t.Fatalf("status = %d, want 401, body=%s", w.Code, w.Body.String())
	}
}

func TestRouterCreateTenantEndToEnd(t *testing.T) {
	newTestDB(t)
	auth := newTestAuthEnv(t)
	mux := NewRouter()

	// POST /v1/tenants has no {tenant_id} path parameter, so any
	// otherwise-valid token works — there's no organization to match.
	r := httptest.NewRequest("POST", "/v1/tenants", strings.NewReader(`{"name":"Acme Bank","plan_id":"plan_std"}`))
	auth.setAuthHeaders(r, "irrelevant-since-no-tenant_id-path-param")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	if w.Code != 202 {
		t.Fatalf("status = %d, want 202, body=%s", w.Code, w.Body.String())
	}
}
