// Command saasapi runs the external, customer/CloudXP-facing SaaS API
// service described in docs/design/cloudxp-machine-manager-api-design.md.
// It is a separate binary from farmer/sprout/grlx: it owns the `saas`
// schema in the shared PXC cluster and talks to farmer only over
// privileged internal NATS subjects (§2.2), as its own narrowly-scoped
// User under the bus's SYS Account — see
// docs/design/grlx-internal-api-account.md and internal/saasapi/bus.go.
package main

import (
	"context"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/valkey-io/valkey-go"

	"github.com/gogrlx/grlx/v2/internal/heartbeat"
	log "github.com/gogrlx/grlx/v2/internal/log"
	"github.com/gogrlx/grlx/v2/internal/saasapi"
)

func main() {
	cfg, err := saasapi.LoadConfig()
	if err != nil {
		log.Fatalf("saasapi: invalid configuration: %v", err)
	}

	db, err := saasapi.OpenDB(cfg.DSN)
	if err != nil {
		log.Fatalf("saasapi: failed to open saas schema: %v", err)
	}
	saasapi.SetDB(db)

	// Fail closed on Valkey when it's configured: a pod that silently
	// fell back to per-pod limiting for its whole life would quietly
	// multiply the limit by the replica count. Once running, a Valkey
	// error on an individual request falls back to this pod's own limit
	// instead (see saasapi.NewValkeyLimiter). Client-side caching is off:
	// neither the limiter nor heartbeat.IsOnline reads a cacheable value.
	var vc valkey.Client
	if len(cfg.ValkeyAddrs) > 0 {
		vc, err = valkey.NewClient(valkey.ClientOption{InitAddress: cfg.ValkeyAddrs, DisableCache: true})
		if err != nil {
			log.Fatalf("saasapi: failed to connect to Valkey at %v: %v", cfg.ValkeyAddrs, err)
		}
		defer vc.Close()
	}
	initHeartbeatClient(vc)

	// Before NewRouter, which wires the limiter in effect at that moment
	// into POST .../enrollment-keys.
	if err := saasapi.SetEnrollmentKeyRateLimit(cfg.EnrollmentKeyRateLimit, cfg.EnrollmentKeyRateBurst, vc); err != nil {
		log.Fatalf("saasapi: %v", err)
	}
	scope := "per pod (SAASAPI_VALKEY_ADDRS unset)"
	if vc != nil {
		scope = "across all pods via Valkey"
	}
	log.Infof("saasapi: enrollment-key issuance limited to %g req/s per tenant, burst %d, %s",
		cfg.EnrollmentKeyRateLimit, cfg.EnrollmentKeyRateBurst, scope)

	// A background context: the JWKS cache's auto-refresh goroutine
	// (see NewAuthConfig) should live for the whole process, not just
	// until shutdown starts.
	authCfg, err := saasapi.NewAuthConfig(context.Background(),
		cfg.InternalAuthSecretCurrent, cfg.InternalAuthSecretPrevious,
		cfg.KeycloakJWKSURL, cfg.JWTIssuer, cfg.JWTAudience)
	if err != nil {
		log.Fatalf("saasapi: failed to configure auth: %v", err)
	}
	saasapi.SetAuthConfig(authCfg)

	// Fail closed on the NATS connection (see ConnectBus's doc comment and
	// the design doc's "SaaS API boot posture"): unlike farmer's
	// per-tenant connections, this is the single connection every async
	// tenant operation depends on, and a replica that accepted POST
	// /tenants without it would leave tenants pending with nothing to move
	// them forward. Kubernetes' restart backoff is the retry loop.
	nc, err := saasapi.ConnectBus(cfg)
	if err != nil {
		log.Fatalf("saasapi: failed to connect to the NATS bus: %v", err)
	}
	if err := saasapi.StartProvisioningResultListener(nc); err != nil {
		log.Fatalf("saasapi: failed to subscribe to provisioning results: %v", err)
	}
	saasapi.SetBus(nc)
	log.Infof("saasapi: connected to the NATS bus at %s", nc.ConnectedUrl())

	// Plain HTTP: TLS termination is assumed to happen at the gateway
	// (Envoy, workstream H) in front of this service, consistent with the
	// design doc's architecture diagram (§0) showing CloudXP/tenants
	// reaching the SaaS API over REST without this binary owning certs.
	srv := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      newRouter(cfg),
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  cfg.IdleTimeout,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		log.Infof("saasapi: listening on %s", cfg.ListenAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("saasapi: server failed: %v", err)
		}
	}()

	<-ctx.Done()
	stop()
	log.Info("saasapi: shutdown signal received")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Errorf("saasapi: shutdown error: %v", err)
	}
	// After the HTTP server has stopped (no more dispatches): Drain flushes
	// any buffered publishes and lets in-flight result handlers finish
	// before closing. It's asynchronous, so wait (bounded) for the close.
	if err := nc.Drain(); err != nil {
		log.Errorf("saasapi: draining NATS connection: %v", err)
	}
	for deadline := time.Now().Add(5 * time.Second); !nc.IsClosed() && time.Now().Before(deadline); {
		time.Sleep(50 * time.Millisecond)
	}
	log.Info("saasapi: stopped")
}

// newRouter builds the HTTP router with cfg's feature flags applied. The
// fleet update dispatch flag must be set before saasapi.NewRouter, which
// registers POST .../sprouts/updates and GET .../sprouts/updates/{batch_id}
// only if the flag is on at that moment (SAASAPI_FLEET_UPDATE_DISPATCH_ENABLED,
// default off: sprout self-update is still disabled upstream,
// gogrlx/grlx#286).
func newRouter(cfg saasapi.Config) *http.ServeMux {
	saasapi.SetFleetUpdateDispatchEnabled(cfg.FleetUpdateDispatchEnabled)
	return saasapi.NewRouter()
}

// initHeartbeatClient points internal/heartbeat at the same Valkey client
// the enrollment-key limiter uses, so heartbeat.IsOnline — which fills
// the `connected` field of GET .../sprouts?asset_ids= (§1.4) — reads the
// live keys farmer's heartbeat listener writes. It's the saasapi counterpart of
// cmd/farmer's initHeartbeatClient. SAASAPI_VALKEY_ADDRS must therefore
// name the Valkey farmer writes heartbeats to. With it unset, vc is nil
// and heartbeat is left unwired: IsOnline reports false for every sprout,
// i.e. `connected: false`.
func initHeartbeatClient(vc valkey.Client) {
	if vc != nil {
		heartbeat.SetClient(vc)
	}
}
