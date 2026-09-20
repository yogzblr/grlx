package saasapi

import (
	"net/http"
	"time"

	log "github.com/gogrlx/grlx/v2/internal/log"
)

// Logger wraps a handler with request logging, matching internal/api's
// farmer-side Logger middleware.
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
