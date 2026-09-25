package saasapi

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLoadConfigEnrollmentKeyRateLimitDefaults(t *testing.T) {
	t.Setenv("SAASAPI_ENROLLMENT_KEY_RATE_LIMIT", "")
	t.Setenv("SAASAPI_ENROLLMENT_KEY_RATE_BURST", "")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.EnrollmentKeyRateLimit != float64(enrollmentKeyIssuanceRate) {
		t.Fatalf("EnrollmentKeyRateLimit = %v, want default %v", cfg.EnrollmentKeyRateLimit, enrollmentKeyIssuanceRate)
	}
	if cfg.EnrollmentKeyRateBurst != enrollmentKeyIssuanceBurst {
		t.Fatalf("EnrollmentKeyRateBurst = %d, want default %d", cfg.EnrollmentKeyRateBurst, enrollmentKeyIssuanceBurst)
	}
}

func TestLoadConfigEnrollmentKeyRateLimitOverride(t *testing.T) {
	t.Setenv("SAASAPI_ENROLLMENT_KEY_RATE_LIMIT", "0.5")
	t.Setenv("SAASAPI_ENROLLMENT_KEY_RATE_BURST", "20")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.EnrollmentKeyRateLimit != 0.5 {
		t.Fatalf("EnrollmentKeyRateLimit = %v, want 0.5", cfg.EnrollmentKeyRateLimit)
	}
	if cfg.EnrollmentKeyRateBurst != 20 {
		t.Fatalf("EnrollmentKeyRateBurst = %d, want 20", cfg.EnrollmentKeyRateBurst)
	}
}

// TestLoadConfigEnrollmentKeyRateLimitRejectsInvalid: a bad value is a
// startup error naming the variable, never a silent fallback to the
// default or a setting that disables the limit (0, negative, NaN, Inf).
func TestLoadConfigEnrollmentKeyRateLimitRejectsInvalid(t *testing.T) {
	cases := []struct {
		rateLimit, burst string
	}{
		{"fast", ""},
		{"0", ""},
		{"-1", ""},
		{"NaN", ""},
		{"Inf", ""},
		{"", "many"},
		{"", "0"},
		{"", "-3"},
		{"", "2.5"},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("rate=%q,burst=%q", c.rateLimit, c.burst), func(t *testing.T) {
			t.Setenv("SAASAPI_ENROLLMENT_KEY_RATE_LIMIT", c.rateLimit)
			t.Setenv("SAASAPI_ENROLLMENT_KEY_RATE_BURST", c.burst)
			_, err := LoadConfig()
			if err == nil {
				t.Fatalf("expected an error")
			}
			if !strings.Contains(err.Error(), "SAASAPI_ENROLLMENT_KEY_RATE_") {
				t.Fatalf("error should name the env var, got: %v", err)
			}
		})
	}
}

func TestSetEnrollmentKeyRateLimitRejectsInvalid(t *testing.T) {
	saved := enrollmentKeyIssuanceLimiter
	t.Cleanup(func() { enrollmentKeyIssuanceLimiter = saved })

	for _, c := range []struct {
		perSecond float64
		burst     int
	}{{0, 5}, {-1, 5}, {1, 0}} {
		if err := SetEnrollmentKeyRateLimit(c.perSecond, c.burst, nil); err == nil {
			t.Fatalf("SetEnrollmentKeyRateLimit(%v, %d): expected an error", c.perSecond, c.burst)
		}
		if enrollmentKeyIssuanceLimiter != saved {
			t.Fatalf("a rejected setting must leave the existing limiter in place")
		}
	}
}

// TestSetEnrollmentKeyRateLimitAppliesToRouter: a configured burst, not
// the compiled-in default, is what the real route enforces.
func TestSetEnrollmentKeyRateLimitAppliesToRouter(t *testing.T) {
	newTestDB(t)
	auth := newTestAuthEnv(t)
	tenantID := mustCreateTenant(t, "Acme Bank")

	saved := enrollmentKeyIssuanceLimiter
	t.Cleanup(func() { enrollmentKeyIssuanceLimiter = saved })

	const burst = enrollmentKeyIssuanceBurst + 3
	if err := SetEnrollmentKeyRateLimit(0.001, burst, nil); err != nil {
		t.Fatalf("SetEnrollmentKeyRateLimit: %v", err)
	}
	mux := NewRouter()

	body := `{"expires_in_hours":24,"max_uses":50}`
	for i := 0; i <= burst; i++ {
		r := httptest.NewRequest("POST", "/v1/tenants/"+tenantID+"/enrollment-keys", strings.NewReader(body))
		auth.setAuthHeaders(r, tenantID)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		switch {
		case i < burst && w.Code != http.StatusOK:
			t.Fatalf("request %d within configured burst %d: status = %d, want 200, body=%s", i, burst, w.Code, w.Body.String())
		case i == burst && w.Code != http.StatusTooManyRequests:
			t.Fatalf("request %d beyond configured burst %d: status = %d, want 429", i, burst, w.Code)
		}
	}
}
