// Command saasapi runs the external, customer/CloudXP-facing SaaS API
// service described in docs/design/cloudxp-machine-manager-api-design.md.
// It is a separate binary from farmer/sprout/grlx: it owns the `saas`
// schema in the shared PXC cluster and talks to farmer only over
// privileged internal NATS subjects (§2.2) — not implemented yet in this
// scaffold, see internal/saasapi/provisioning.go.
package main

import (
	"context"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	log "github.com/gogrlx/grlx/v2/internal/log"
	"github.com/gogrlx/grlx/v2/internal/saasapi"
)

func main() {
	cfg := saasapi.LoadConfig()

	db, err := saasapi.OpenDB(cfg.DSN)
	if err != nil {
		log.Fatalf("saasapi: failed to open saas schema: %v", err)
	}
	saasapi.SetDB(db)

	// Plain HTTP: TLS termination is assumed to happen at the gateway
	// (Envoy, workstream H) in front of this service, consistent with the
	// design doc's architecture diagram (§0) showing CloudXP/tenants
	// reaching the SaaS API over REST without this binary owning certs.
	srv := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      saasapi.NewRouter(),
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
	log.Info("saasapi: stopped")
}
