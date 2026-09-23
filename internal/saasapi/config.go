// Package saasapi implements the external, customer/CloudXP-facing SaaS
// API service described in docs/design/cloudxp-machine-manager-api-design.md.
// It owns the `saas` schema in the shared PXC cluster and never writes to
// the `farmer` schema (see the design doc's §5.1 grants).
package saasapi

import (
	"os"
	"time"
)

// Config holds the saasapi service's runtime configuration. Unlike
// farmer/sprout/grlx, this is a standalone service with its own env-based
// config rather than a new binary wired into internal/config's jety
// loader.
//
// Auth (see middleware.go's Auth and NewAuthConfig) is configured from
// this same env-var surface, read once at process startup:
//
//   - INTERNAL_AUTH_SECRET_CURRENT / INTERNAL_AUTH_SECRET_PREVIOUS: the
//     BFF's shared service secret (layer 1). Sourced from a Kubernetes
//     Secret kept in sync with Vault/OpenBao by External Secrets
//     Operator, with Reloader triggering a rolling restart on change.
//     Read once here, not polled or hot-reloaded — see middleware.go for
//     why two values exist.
//   - SAASAPI_KEYCLOAK_JWKS_URL / SAASAPI_JWT_ISSUER /
//     SAASAPI_JWT_AUDIENCE: the Keycloak realm whose end-user JWTs the
//     BFF forwards (layer 2).
//
// The NATS connection to farmer (see bus.go's ConnectBus, and
// docs/design/grlx-internal-api-account.md) is configured the same way:
//
//   - SAASAPI_NATS_NKEY_SEED / SAASAPI_NATS_USER_JWT: this service's own
//     NATS identity — a narrowly-scoped User under the bus's SYS Account,
//     minted by farmer (pki.EnsureSaaSAPICredential). Same operational
//     model as INTERNAL_AUTH_SECRET_*: a Kubernetes Secret kept in sync
//     with OpenBao by External Secrets Operator, Reloader rolling the
//     Deployment on rotation, read once here at startup. The seed is the
//     secret half; the JWT isn't secret but must travel with it.
//   - SAASAPI_NATS_URL: the bus's client URL (e.g. "nats://farmerbus:4222";
//     TLS is always required, the scheme notwithstanding).
//   - SAASAPI_NATS_CA_FILE: path to the root CA PEM that signed the bus's
//     server certificate — the same config.RootCA farmer's own
//     connections trust.
type Config struct {
	// ListenAddr is the address the HTTP server binds to, e.g. ":8081".
	ListenAddr string
	// DSN is the GORM MySQL DSN for the shared PXC cluster's `saas` schema,
	// e.g. "saas_svc:pass@tcp(pxc-cluster:3306)/saas?parseTime=true".
	DSN string

	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration

	// InternalAuthSecretCurrent is the required, currently-valid shared
	// service secret the BFF presents on X-Internal-Auth.
	InternalAuthSecretCurrent string
	// InternalAuthSecretPrevious is the previous secret value, still
	// accepted during a rotation window. Empty means only Current is
	// accepted.
	InternalAuthSecretPrevious string

	// KeycloakJWKSURL is the Keycloak realm's JWKS endpoint, e.g.
	// "https://keycloak.example.com/realms/cloudxp/protocol/openid-connect/certs".
	KeycloakJWKSURL string
	// JWTIssuer is the expected "iss" claim on end-user JWTs.
	JWTIssuer string
	// JWTAudience is the expected "aud" claim on end-user JWTs.
	JWTAudience string

	// NATSURL is the farmer bus's client URL.
	NATSURL string
	// NATSCAFile is the path to the root CA PEM used to verify the bus's
	// TLS certificate.
	NATSCAFile string
	// NATSNKeySeed is this service's NATS User NKey seed ("SU...").
	NATSNKeySeed string
	// NATSUserJWT is this service's signed NATS User JWT.
	NATSUserJWT string
}

// LoadConfig reads the saasapi service's configuration from environment
// variables, applying sane defaults where possible.
func LoadConfig() Config {
	cfg := Config{
		ListenAddr:   envOrDefault("SAASAPI_LISTEN_ADDR", ":8081"),
		DSN:          os.Getenv("SAASAPI_DSN"),
		ReadTimeout:  20 * time.Second,
		WriteTimeout: 20 * time.Second,
		IdleTimeout:  60 * time.Second,

		InternalAuthSecretCurrent:  os.Getenv("INTERNAL_AUTH_SECRET_CURRENT"),
		InternalAuthSecretPrevious: os.Getenv("INTERNAL_AUTH_SECRET_PREVIOUS"),

		KeycloakJWKSURL: os.Getenv("SAASAPI_KEYCLOAK_JWKS_URL"),
		JWTIssuer:       os.Getenv("SAASAPI_JWT_ISSUER"),
		JWTAudience:     os.Getenv("SAASAPI_JWT_AUDIENCE"),

		NATSURL:      os.Getenv("SAASAPI_NATS_URL"),
		NATSCAFile:   os.Getenv("SAASAPI_NATS_CA_FILE"),
		NATSNKeySeed: os.Getenv("SAASAPI_NATS_NKEY_SEED"),
		NATSUserJWT:  os.Getenv("SAASAPI_NATS_USER_JWT"),
	}
	return cfg
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
