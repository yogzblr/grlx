package saasapi

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRouterRequiresAuthHeader(t *testing.T) {
	newTestDB(t)
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
	mux := NewRouter()

	r := httptest.NewRequest("POST", "/v1/tenants", strings.NewReader(`{"name":"Acme Bank","plan_id":"plan_std"}`))
	r.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	if w.Code != 202 {
		t.Fatalf("status = %d, want 202, body=%s", w.Code, w.Body.String())
	}
}
