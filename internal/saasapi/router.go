package saasapi

import (
	"net/http"

	"golang.org/x/time/rate"
)

// enrollmentKeyIssuanceRate/Burst bound how often a single caller (see
// RateLimit's key choice in middleware.go) may call POST
// .../enrollment-keys. This is a mutating, credential-issuing endpoint
// sitting behind Auth, not an unauthenticated guessing target — unlike
// NIST SP 800-63B's "cap failed attempts" figure, which bounds
// verification attempts against a secret at the not-yet-built §3.2/§3.3
// redemption endpoint, this number only needs to bound ordinary abuse of
// a leaked or over-eager bearer token (someone scripting key creation in
// a loop), not defend against brute-forcing a secret. 1 request/second
// sustained with a burst of 5 comfortably covers a legitimate
// bulk-onboarding script while still capping a spamming caller at a few
// hundred enrollment_keys rows/minute instead of an unbounded flood.
const (
	enrollmentKeyIssuanceRate  rate.Limit = 1
	enrollmentKeyIssuanceBurst int        = 5
)

var enrollmentKeyIssuanceLimiter = NewPerCallerLimiter(enrollmentKeyIssuanceRate, enrollmentKeyIssuanceBurst)

// NewRouter builds the SaaS API's HTTP router (design doc §1.1, §1.2).
// Every route is wrapped in Auth — see middleware.go for what that
// currently does and does not check.
func NewRouter() *http.ServeMux {
	mux := http.NewServeMux()

	route(mux, "POST /v1/tenants", CreateTenant, "CreateTenant")
	route(mux, "GET /v1/tenants/{tenant_id}", GetTenant, "GetTenant")
	route(mux, "PATCH /v1/tenants/{tenant_id}", PatchTenant, "PatchTenant")
	route(mux, "DELETE /v1/tenants/{tenant_id}", DeleteTenant, "DeleteTenant")
	route(mux, "GET /v1/tenants/{tenant_id}/status", GetTenantStatus, "GetTenantStatus")

	// POST .../enrollment-keys mints a new credential and is the one
	// enrollment-key route that lets a caller grow saas.enrollment_keys
	// without bound, so it's rate-limited (see enrollmentKeyIssuanceRate
	// above). GET (listing) and DELETE (revocation) are left to Auth's
	// gate alone: listing is read-only and returns no secret material
	// (§1.2's list response excludes key_hash), and revoking is bounded
	// by however many keys already exist — repeatedly revoking the same
	// key is a no-op, not a way to grow state or mint anything.
	routeRateLimited(mux, "POST /v1/tenants/{tenant_id}/enrollment-keys", CreateEnrollmentKey,
		"CreateEnrollmentKey", enrollmentKeyIssuanceLimiter)
	route(mux, "GET /v1/tenants/{tenant_id}/enrollment-keys", ListEnrollmentKeys, "ListEnrollmentKeys")
	route(mux, "DELETE /v1/tenants/{tenant_id}/enrollment-keys/{key_id}", DeleteEnrollmentKey, "DeleteEnrollmentKey")

	return mux
}

func route(mux *http.ServeMux, pattern string, h http.HandlerFunc, name string) {
	mux.Handle(pattern, Logger(Auth(h, name), name))
}

// routeRateLimited is route plus a per-caller RateLimit gate, applied
// after Auth so an unauthenticated request (rejected by Auth before it
// ever reaches RateLimit) doesn't consume rate-limit bookkeeping.
func routeRateLimited(mux *http.ServeMux, pattern string, h http.HandlerFunc, name string, limiter *perCallerLimiter) {
	mux.Handle(pattern, Logger(Auth(RateLimit(h, limiter), name), name))
}
