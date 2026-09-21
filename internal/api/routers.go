package api

import (
	"net/http"

	"github.com/gogrlx/grlx/v2/internal/api/handlers"
)

// NewRouter creates an http.ServeMux for the farmer's HTTPS server.
// This server handles:
//   - PKI bootstrap: sprouts without NATS credentials fetch the CA
//     certificate and register their NKey here.
//   - Enrollment (POST /v1/enroll): the join-token-based path that mints a
//     sprout's JWT/NKey identity in one round trip — see
//     docs/design/grlx-envoy-enrollment-design.md.
//   - File serving: sprouts download recipe files via the farmer:// scheme,
//     read from object storage (see handlers.SetRecipeStore) rather than
//     local disk — docs/design/grlx-master-plan.md Phase 1.
//   - Health checks: an unauthenticated /health endpoint for monitoring
//     and automated tooling.
func NewRouter(certificate string) *http.ServeMux {
	_ = certificate // reserved for future TLS configuration
	mux := http.NewServeMux()

	// PKI bootstrap routes (no auth required — pre-enrollment sprouts use these)
	mux.Handle("GET /auth/cert/", Logger(http.HandlerFunc(handlers.GetCertificate), "GetCertificate"))
	mux.Handle("PUT /pki/putnkey", Logger(http.HandlerFunc(handlers.PutNKey), "PutNKey"))

	// Sprout enrollment (docs/design/grlx-envoy-enrollment-design.md,
	// cloudxp-machine-manager-api-design.md §3.2) — also no auth required,
	// for the same reason as the PKI bootstrap routes above: a sprout
	// calling this has no JWT yet. Authorization here is the join token
	// itself, validated inside handlers.Enroll/pki.Enroll.
	mux.Handle("POST /v1/enroll", Logger(http.HandlerFunc(handlers.Enroll), "Enroll"))

	// Gateway JWT JWKS (design doc §2.4 per the "Gateway JWT Companion
	// Token" brief) — public keys only, no auth required. What Envoy's
	// jwt_authn remote_jwks (deploy/envoy/envoy.yaml) fetches.
	mux.Handle("GET /v1/.well-known/jwks.json", Logger(http.HandlerFunc(handlers.JWKS), "JWKS"))

	// Health check (unauthenticated).
	mux.Handle("GET /health", Logger(http.HandlerFunc(handlers.GetHealth), "GetHealth"))

	// File server: serves recipe files over HTTPS (farmer:// scheme).
	mux.Handle("GET /files/", Logger(Auth(http.HandlerFunc(handlers.GetFile), "FileServer"), "FileServer"))

	return mux
}
