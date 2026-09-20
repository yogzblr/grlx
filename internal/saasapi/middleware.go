package saasapi

import (
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"

	log "github.com/gogrlx/grlx/v2/internal/log"
)

// Logger wraps a handler with request logging, matching internal/api's
// farmer-side Logger middleware.
//
// Security note (part of the enrollment-key logging-safety review): this
// logs exactly four values — method, URI, route name, and duration. It
// never touches r.Body, so it cannot leak a request payload (an
// enrollment-key POST body, a tenant PATCH body, etc.) no matter what
// that payload contains. See TestLoggerNeverLogsRequestBody in
// middleware_test.go, which pins this by asserting a recognizable value
// from a request body never appears in Logger's output.
func Logger(inner http.Handler, name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		inner.ServeHTTP(w, r)
		log.Tracef("%s %s %s %s", r.Method, r.RequestURI, name, time.Since(start))
	})
}

// Auth is a placeholder for the bearer-token/tenant-claim auth the design
// doc describes (§1: "All endpoints require a bearer token whose claims
// include the caller's tenant_id"). Human-user auth for the SaaS API
// (API keys vs. SSO/OIDC) is explicitly listed as not yet designed (§1.7,
// §6), so there is no concrete scheme to implement yet.
//
// This stub only performs the one check that doesn't depend on the
// undecided scheme: it requires *some* Authorization header to be
// present, so routes aren't accidentally left wide open. It does NOT
// verify the token or extract/enforce a tenant_id claim — every handler
// in this package trusts the {tenant_id} path parameter as-is. Wiring
// real verification (and re-checking path tenant_id against the token's
// claim, per §4's tenant-safety convention) is required before this
// service is exposed beyond internal testing.
//
// TODO(§1.7/§6): replace with real bearer-token verification once the
// SaaS API's human-user auth scheme is designed.
func Auth(inner http.Handler, name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			writeError(w, http.StatusUnauthorized, "unauthorized", "missing Authorization header")
			return
		}
		inner.ServeHTTP(w, r)
	})
}

// callerBucketTTL bounds how long an idle per-caller bucket is kept
// around. Without eviction, perCallerLimiter's map would grow without
// bound under Auth's current stopgap keying (see below) — a caller can
// trivially get a fresh bucket per request just by varying the
// Authorization header value, which is also why this limiter is not a
// real defense yet, only a bound on accidental/lazy abuse (a script or a
// leaked token hammering the same header value repeatedly).
const callerBucketTTL = 10 * time.Minute

// callerBucket is one caller's token bucket plus bookkeeping for
// eviction.
type callerBucket struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// perCallerLimiter is a small, reusable per-caller token-bucket rate
// limiter. It exists as its own named type (rather than inlined into the
// RateLimit middleware function) so the future /v1/enroll redemption
// endpoint (design doc §3.2/§3.3 — the caller-presents-a-key,
// server-validates-it flow; not implemented anywhere in this codebase
// yet) can construct its own instance here, with a much stricter,
// NIST-SP-800-63B-aligned rate for verification attempts specifically,
// without duplicating this bucketing/eviction logic.
type perCallerLimiter struct {
	mu      sync.Mutex
	limit   rate.Limit
	burst   int
	callers map[string]*callerBucket
}

// NewPerCallerLimiter builds a perCallerLimiter allowing r events/second
// sustained, with bursts up to burst, tracked independently per caller
// key.
func NewPerCallerLimiter(r rate.Limit, burst int) *perCallerLimiter {
	return &perCallerLimiter{
		limit:   r,
		burst:   burst,
		callers: make(map[string]*callerBucket),
	}
}

// allow reports whether a request from key is allowed right now.
func (l *perCallerLimiter) allow(key string) bool {
	return l.allowAt(key, time.Now())
}

// allowAt is allow with an explicit clock, so tests can drive the
// limiter deterministically (advancing a fake "now") instead of
// sleeping in real time.
func (l *perCallerLimiter) allowAt(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.evictLocked(now)

	b, ok := l.callers[key]
	if !ok {
		b = &callerBucket{limiter: rate.NewLimiter(l.limit, l.burst)}
		l.callers[key] = b
	}
	b.lastSeen = now
	return b.limiter.AllowN(now, 1)
}

// evictLocked drops buckets that have been idle longer than
// callerBucketTTL. Must be called with l.mu held.
func (l *perCallerLimiter) evictLocked(now time.Time) {
	cutoff := now.Add(-callerBucketTTL)
	for k, b := range l.callers {
		if b.lastSeen.Before(cutoff) {
			delete(l.callers, k)
		}
	}
}

// RateLimit wraps a handler with a per-caller rate limit (design doc §3's
// security-review concerns, extended here to enrollment-key issuance —
// see router.go for which routes use this).
//
// Keying: since Auth today only checks that *some* Authorization header
// is present (no real token parsing — see Auth's own TODO), this keys
// buckets by the raw Authorization header value. That's a deliberate
// stopgap, not a real caller identity: it groups requests that reuse the
// same header value, but a caller can trivially get a fresh bucket by
// sending a different (even garbage) header value each time. Once real
// auth lands (§1.7/§6), this should key by the authenticated tenant_id
// or API key ID instead, which can't be spoofed by the caller.
func RateLimit(inner http.Handler, limiter *perCallerLimiter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("Authorization")
		if !limiter.allow(key) {
			writeError(w, http.StatusTooManyRequests, "rate_limited", "too many requests, slow down and retry later")
			return
		}
		inner.ServeHTTP(w, r)
	})
}
