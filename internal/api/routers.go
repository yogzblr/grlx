package api

import (
	"net/http"

	"github.com/gogrlx/grlx/v2/internal/api/handlers"
)

// NewRouter creates an http.ServeMux for the farmer's HTTPS server.
// This server handles:
//   - PKI bootstrap: sprouts without NATS credentials fetch the CA
//     certificate and register their NKey here.
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

	// Health check (unauthenticated).
	mux.Handle("GET /health", Logger(http.HandlerFunc(handlers.GetHealth), "GetHealth"))

	// File server: serves recipe files over HTTPS (farmer:// scheme).
	mux.Handle("GET /files/", Logger(Auth(http.HandlerFunc(handlers.GetFile), "FileServer"), "FileServer"))

	return mux
}
