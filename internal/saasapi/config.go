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
// loader — the design doc's §1.7/§6 human-user auth model isn't settled
// yet, so there's no shared config surface to plug into.
type Config struct {
	// ListenAddr is the address the HTTP server binds to, e.g. ":8081".
	ListenAddr string
	// DSN is the GORM MySQL DSN for the shared PXC cluster's `saas` schema,
	// e.g. "saas_svc:pass@tcp(pxc-cluster:3306)/saas?parseTime=true".
	DSN string

	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
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
	}
	return cfg
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
