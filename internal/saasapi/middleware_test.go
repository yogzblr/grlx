package saasapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

func TestPerCallerLimiterAllowsBurstThenBlocks(t *testing.T) {
	l := NewPerCallerLimiter(rate.Limit(1), 3)
	now := time.Now()

	for i := 0; i < 3; i++ {
		if !l.allowAt("caller-a", now) {
			t.Fatalf("request %d within burst should be allowed", i)
		}
	}
	if l.allowAt("caller-a", now) {
		t.Fatalf("request beyond burst should be denied")
	}
}

func TestPerCallerLimiterRefillsAfterWindow(t *testing.T) {
	l := NewPerCallerLimiter(rate.Limit(1), 1) // 1/sec, burst 1
	now := time.Now()

	if !l.allowAt("caller-a", now) {
		t.Fatalf("first request should be allowed")
	}
	if l.allowAt("caller-a", now) {
		t.Fatalf("immediate second request should be denied")
	}
	// Advance a fake clock past the refill window instead of sleeping.
	if !l.allowAt("caller-a", now.Add(1100*time.Millisecond)) {
		t.Fatalf("request after the refill window should be allowed")
	}
}

func TestPerCallerLimiterKeysAreIndependent(t *testing.T) {
	l := NewPerCallerLimiter(rate.Limit(1), 1)
	now := time.Now()

	if !l.allowAt("caller-a", now) {
		t.Fatalf("caller-a's first request should be allowed")
	}
	if !l.allowAt("caller-b", now) {
		t.Fatalf("caller-b should have its own bucket, independent of caller-a")
	}
	if l.allowAt("caller-a", now) {
		t.Fatalf("caller-a should still be limited by its own bucket")
	}
}

func TestPerCallerLimiterEvictsIdleBuckets(t *testing.T) {
	l := NewPerCallerLimiter(rate.Limit(1), 1)
	now := time.Now()

	l.allowAt("caller-a", now)
	if len(l.callers) != 1 {
		t.Fatalf("expected 1 tracked caller, got %d", len(l.callers))
	}

	// A later call, long past callerBucketTTL, should sweep the idle
	// bucket rather than let the map grow forever.
	l.allowAt("caller-b", now.Add(callerBucketTTL+time.Second))
	if _, stillThere := l.callers["caller-a"]; stillThere {
		t.Fatalf("expected caller-a's idle bucket to be evicted")
	}
}

// newTenantRequest builds a request as RateLimit sees it inside Auth:
// with the verified organization already on the context.
func newTenantRequest(tenantID, authorization string) *http.Request {
	r := httptest.NewRequest("POST", "/v1/tenants/"+tenantID+"/enrollment-keys", nil)
	r.Header.Set("Authorization", authorization)
	return r.WithContext(withOrganization(r.Context(), Organization{ID: tenantID}))
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func TestRateLimitMiddlewareReturns429(t *testing.T) {
	h := RateLimit(okHandler(), NewPerCallerLimiter(rate.Limit(1), 1))

	w1 := httptest.NewRecorder()
	h.ServeHTTP(w1, newTenantRequest("t_x", "Bearer same-token"))
	if w1.Code != http.StatusOK {
		t.Fatalf("first request status = %d, want 200", w1.Code)
	}

	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, newTenantRequest("t_x", "Bearer same-token"))
	if w2.Code != http.StatusTooManyRequests {
		t.Fatalf("second request status = %d, want 429, body=%s", w2.Code, w2.Body.String())
	}

	var errResp errorResponse
	if err := json.Unmarshal(w2.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("decoding error response: %v", err)
	}
	if errResp.Error != "rate_limited" {
		t.Fatalf("error code = %q, want rate_limited", errResp.Error)
	}
}

// TestRateLimitMiddlewareKeysByTenantNotToken pins the per-tenant key:
// a different Authorization value for the same tenant shares the
// tenant's bucket (varying the token no longer dodges the limit), while
// a different tenant gets a bucket of its own.
func TestRateLimitMiddlewareKeysByTenantNotToken(t *testing.T) {
	h := RateLimit(okHandler(), NewPerCallerLimiter(rate.Limit(1), 1))

	w := httptest.NewRecorder()
	h.ServeHTTP(w, newTenantRequest("t_a", "Bearer token-1"))
	if w.Code != http.StatusOK {
		t.Fatalf("t_a first request: status = %d, want 200", w.Code)
	}

	w = httptest.NewRecorder()
	h.ServeHTTP(w, newTenantRequest("t_a", "Bearer token-2"))
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("t_a with a different token: status = %d, want 429 (same tenant, same bucket)", w.Code)
	}

	w = httptest.NewRecorder()
	h.ServeHTTP(w, newTenantRequest("t_b", "Bearer token-1"))
	if w.Code != http.StatusOK {
		t.Fatalf("t_b: status = %d, want 200 (different tenant, own bucket)", w.Code)
	}
}

// TestRateLimitMiddlewareFailsClosedWithoutOrganization covers RateLimit
// wired without Auth in front of it: no organization on the context
// must be rejected, not let through with the limit silently disabled.
func TestRateLimitMiddlewareFailsClosedWithoutOrganization(t *testing.T) {
	called := false
	h := RateLimit(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}), NewPerCallerLimiter(rate.Limit(1), 1))

	r := httptest.NewRequest("POST", "/v1/tenants/t_x/enrollment-keys", nil)
	r.Header.Set("Authorization", "Bearer some-token")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403, body=%s", w.Code, w.Body.String())
	}
	if called {
		t.Fatalf("inner handler must not run when no organization is on the context")
	}
}

func TestRouterRateLimitsEnrollmentKeyIssuance(t *testing.T) {
	newTestDB(t)
	auth := newTestAuthEnv(t)
	tenantID := mustCreateTenant(t, "Acme Bank")
	// Isolate this test from any budget other tests already spent
	// against the package-level enrollmentKeyIssuanceLimiter.
	enrollmentKeyIssuanceLimiter = NewPerCallerLimiter(enrollmentKeyIssuanceRate, enrollmentKeyIssuanceBurst)

	mux := NewRouter()
	body := `{"expires_in_hours":24,"max_uses":50}`

	// Every request presents a different, individually valid token for
	// the same tenant (a distinct organization.name makes each one unique;
	// Ed25519 signing is deterministic, so identical claims minted within
	// the same second would otherwise yield identical tokens). The limit
	// must still trip, because RateLimit keys by the tenant, not the token.
	seen := map[string]bool{}
	var last *httptest.ResponseRecorder
	for i := 0; i < enrollmentKeyIssuanceBurst+1; i++ {
		tok := auth.mintToken(tokenOpts{org: &Organization{ID: tenantID, Name: fmt.Sprintf("user-%d", i)}})
		if seen[tok] {
			t.Fatalf("request %d reused a token; this test needs a distinct token per request", i)
		}
		seen[tok] = true

		r := httptest.NewRequest("POST", "/v1/tenants/"+tenantID+"/enrollment-keys", strings.NewReader(body))
		r.Header.Set(InternalAuthHeader, testInternalAuthSecretCurrent)
		r.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if i < enrollmentKeyIssuanceBurst && w.Code != http.StatusOK {
			t.Fatalf("request %d within burst: status = %d, want 200, body=%s", i, w.Code, w.Body.String())
		}
		last = w
	}
	if last.Code != http.StatusTooManyRequests {
		t.Fatalf("request beyond burst status = %d, want 429, body=%s", last.Code, last.Body.String())
	}
}

func TestListEnrollmentKeysIsNotRateLimited(t *testing.T) {
	newTestDB(t)
	auth := newTestAuthEnv(t)
	tenantID := mustCreateTenant(t, "Acme Bank")

	mux := NewRouter()
	bearer := "Bearer " + auth.mintTokenForTenant(tenantID)
	// Far more than the enrollment-key issuance burst — GET listing has
	// no limiter of its own (see router.go's reasoning), so none of
	// these should ever come back 429.
	for i := 0; i < enrollmentKeyIssuanceBurst*3; i++ {
		r := httptest.NewRequest("GET", "/v1/tenants/"+tenantID+"/enrollment-keys", nil)
		r.Header.Set(InternalAuthHeader, testInternalAuthSecretCurrent)
		r.Header.Set("Authorization", bearer)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code == http.StatusTooManyRequests {
			t.Fatalf("request %d: GET enrollment-keys should not be rate-limited, got 429", i)
		}
	}
}

// TestLoggerNeverLogsRequestBody pins the comment on Logger in
// middleware.go: it only logs method/URI/name/duration and never r.Body,
// so a distinctive value from a request body must never show up in its
// output.
func TestLoggerNeverLogsRequestBody(t *testing.T) {
	newTestDB(t)

	const secretLookingPlanID = "plan_do_not_log_me_xyz123"
	h := Logger(http.HandlerFunc(CreateTenant), "CreateTenant")

	output := captureStderr(t, func() {
		body := `{"name":"Acme Bank","plan_id":"` + secretLookingPlanID + `"}`
		r := httptest.NewRequest("POST", "/v1/tenants", strings.NewReader(body))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusAccepted {
			t.Fatalf("status = %d, want 202, body=%s", w.Code, w.Body.String())
		}
	})

	if strings.Contains(output, secretLookingPlanID) {
		t.Fatalf("Logger's output contains request-body content, it must only log method/URI/name/duration: %s", output)
	}
}
