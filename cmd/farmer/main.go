package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	log "github.com/gogrlx/grlx/v2/internal/log"

	"github.com/gogrlx/grlx/v2/internal/api"
	"github.com/gogrlx/grlx/v2/internal/api/handlers"
	"github.com/gogrlx/grlx/v2/internal/audit"
	"github.com/gogrlx/grlx/v2/internal/auth"
	"github.com/gogrlx/grlx/v2/internal/certs"
	"github.com/gogrlx/grlx/v2/internal/config"
	"github.com/gogrlx/grlx/v2/internal/cook"
	"github.com/gogrlx/grlx/v2/internal/facts"
	"github.com/gogrlx/grlx/v2/internal/gatewayjwt"
	"github.com/gogrlx/grlx/v2/internal/heartbeat"
	"github.com/gogrlx/grlx/v2/internal/ingredients/cmd"
	"github.com/gogrlx/grlx/v2/internal/ingredients/test"
	"github.com/gogrlx/grlx/v2/internal/jobs"
	"github.com/gogrlx/grlx/v2/internal/natsapi"
	"github.com/gogrlx/grlx/v2/internal/objectstore"
	"github.com/gogrlx/grlx/v2/internal/pki"
	"github.com/gogrlx/grlx/v2/internal/props"
	"github.com/gogrlx/grlx/v2/internal/pxc"
	"github.com/gogrlx/grlx/v2/internal/rbac"

	nats_server "github.com/nats-io/nats-server/v2/server"
	nats "github.com/nats-io/nats.go"
	valkey "github.com/valkey-io/valkey-go"
)

func init() {
	config.LoadConfig("farmer")
	log.SetLogLevel(config.LogLevel)
}

var (
	// srvMu guards the s and apiServer package globals, which are read by the
	// shutdown path in main and written/read by handleSIGHUP concurrently.
	srvMu         sync.Mutex
	s             *nats_server.Server
	apiServer     *http.Server
	heartbeatConn *nats.Conn
	GitCommit     string
	Tag           string
)

func setNATSServer(v *nats_server.Server) {
	srvMu.Lock()
	s = v
	srvMu.Unlock()
}

func getNATSServer() *nats_server.Server {
	srvMu.Lock()
	defer srvMu.Unlock()
	return s
}

func setAPIServer(v *http.Server) {
	srvMu.Lock()
	apiServer = v
	srvMu.Unlock()
}

func getAPIServer() *http.Server {
	srvMu.Lock()
	defer srvMu.Unlock()
	return apiServer
}

func setHeartbeatConn(v *nats.Conn) {
	srvMu.Lock()
	heartbeatConn = v
	srvMu.Unlock()
}

func getHeartbeatConn() *nats.Conn {
	srvMu.Lock()
	defer srvMu.Unlock()
	return heartbeatConn
}

func main() {
	config.LoadConfig("farmer")
	fmt.Printf("Starting Farmer with URL %s\n", config.FarmerBusURL)
	defer log.Flush()
	initStorage()
	initRecipeStore()
	initGatewaySigner()
	initHeartbeatClient()
	props.LoadStaticProps(config.StaticProps())
	loadCohortRegistry()
	createConfigRoot()
	initAuditLogger()
	loadAuthPolicy()
	pki.SetupPKIFarmer()
	if err := certs.GenCert(); err != nil {
		log.Fatalf("failed to generate TLS certificates: %v", err)
	}
	if err := certs.GenNKey(true); err != nil {
		log.Fatalf("failed to generate farmer NKey: %v", err)
	}
	RunNATSServer()
	initHeartbeatListener()
	StartAPIServer()
	// ctx is cancelled on SIGINT/SIGTERM, driving a graceful shutdown of the
	// cohort refresher, job reaper, NATS connection, NATS server, and API server.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	natsapi.StartCohortRefresher(ctx, config.CohortRefreshInterval)
	farmerDone := make(chan struct{})
	sighupDone := make(chan struct{})
	go ConnectFarmer(ctx, farmerDone)
	go handleSIGHUP(ctx, sighupDone)

	<-ctx.Done()
	stop()
	log.Info("Shutdown signal received, stopping farmer...")
	// Stop the SIGHUP handler first so it can't restart the API server
	// concurrently with the shutdown below (bounded, with a warning).
	select {
	case <-sighupDone:
	case <-time.After(20 * time.Second):
		log.Warn("timed out waiting for SIGHUP handler to stop")
	}
	// Wait for ConnectFarmer to close the NATS client (bounded).
	select {
	case <-farmerDone:
	case <-time.After(10 * time.Second):
		log.Warn("timed out waiting for NATS client to close")
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if srv := getAPIServer(); srv != nil {
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Errorf("API server shutdown error: %v", err)
		}
	}
	if nc := getHeartbeatConn(); nc != nil {
		nc.Close()
	}
	if srv := getNATSServer(); srv != nil {
		srv.Shutdown()
	}
	log.Info("Farmer stopped")
}

// initStorage opens the shared PXC connection PKI, props/facts, and RBAC
// read and write through (see internal/pxc, and each package's own
// store.go) — read-through, no in-memory cache, so every farmer replica
// agrees on the same state. This fixes the cross-replica divergence bug
// props/store.go had under its old per-process in-memory cache (see
// docs/design/grlx-fork-roadmap.md workstream A).
//
// tenant_id scoping (workstream A.1, FLAG FOR SECURITY REVIEW): every
// query in props/pki/rbac's stores includes tenant_id in the same WHERE
// clause as the row's own key — see their store.go doc comments for the
// current seam (config.FarmerOrganization) and why it isn't yet a
// per-request value.
func initStorage() {
	models := append(append(props.Models(), pki.Models()...), rbac.Models()...)
	db, err := pxc.OpenDB(config.PXCDSN, models...)
	if err != nil {
		log.Fatalf("failed to open PXC farmer schema: %v", err)
	}
	props.SetDB(db)
	pki.SetDB(db)
	rbac.SetDB(db)
}

// initRecipeStore opens the object-storage backend recipes are read from
// (see internal/objectstore, internal/cook/store.go) — farmer's old
// local-disk basepath doesn't survive horizontal scaling, since any core
// replica needs to be able to serve any recipe. Git remains the source of
// truth; syncing a merged commit into this bucket is a deploy-time
// concern, not something farmer does at runtime.
func initRecipeStore() {
	store, err := objectstore.Open(objectstore.Config{
		Endpoint:        config.S3Endpoint,
		AccessKeyID:     config.S3AccessKeyID,
		SecretAccessKey: config.S3SecretAccessKey,
		UseSSL:          config.S3UseSSL,
		Bucket:          config.S3Bucket,
	})
	if err != nil {
		log.Fatalf("failed to open recipe object store: %v", err)
	}
	cook.SetStore(store)
	natsapi.SetRecipeStore(store)
	handlers.SetRecipeStore(store)
}

// initGatewaySigner wires up the OpenBao Transit-backed signer for
// gateway JWTs (internal/gatewayjwt) — the standard alg:EdDSA companion
// token Envoy's jwt_authn validates, alongside the native NATS User JWT
// workstream B already mints. Deliberately not fatal if unconfigured
// (see EnvOpenBaoAddr etc. in internal/gatewayjwt/obtransit.go): existing
// deployments/dev setups without GRLX_GATEWAY_OPENBAO_* set should still
// start farmer normally — POST /v1/enroll fails closed
// (pki.ErrEnrollmentFailed) rather than farmer refusing to boot, until an
// operator configures OpenBao Transit for this key.
func initGatewaySigner() {
	signer, err := gatewayjwt.NewGatewaySigner(config.GatewayTransitKeyName)
	if err != nil {
		log.Errorf("gateway JWT signer not configured (POST /v1/enroll will fail until it is): %v", err)
		return
	}
	pki.SetGatewaySigner(signer)
	handlers.SetGatewaySigner(signer)
	log.Info("Gateway JWT signer configured")
}

// initHeartbeatClient connects the Valkey client connection-state reads
// and writes through (see internal/heartbeat). The $SYS event listener
// itself is registered separately, by initHeartbeatListener, once the bus
// is up.
func initHeartbeatClient() {
	addrs := strings.Split(config.ValkeyAddrs, ",")
	client, err := valkey.NewClient(valkey.ClientOption{InitAddress: addrs})
	if err != nil {
		log.Errorf("failed to connect to Valkey at %v: %v", addrs, err)
		return
	}
	heartbeat.SetClient(client)
}

// initHeartbeatListener subscribes to the bus's own
// $SYS.ACCOUNT.*.CONNECT/DISCONNECT events (as the SYS account — see
// pki.ConnectSystemAccount) and maintains Valkey heartbeat keys from them,
// replacing the old synchronous ping-based probeSprout. Must run after
// RunNATSServer, since the bus needs to be reachable to connect to.
func initHeartbeatListener() {
	nc, err := pki.ConnectSystemAccount()
	if err != nil {
		log.Errorf("failed to connect heartbeat listener to the bus as the SYS account: %v", err)
		return
	}
	if err := heartbeat.RegisterListener(nc); err != nil {
		log.Errorf("failed to register heartbeat listener: %v", err)
		nc.Close()
		return
	}
	setHeartbeatConn(nc)
	log.Info("Heartbeat listener registered")
}

func initAuditLogger() {
	auditDir := config.AuditLogDir
	if auditDir == "" {
		auditDir = "/var/log/grlx/audit"
	}
	logger, err := audit.NewLogger(auditDir)
	if err != nil {
		log.Errorf("Failed to initialize audit logger at %s: %v", auditDir, err)
		return
	}
	audit.SetGlobal(logger)
	audit.SetIdentityResolver(auth.WhoAmI)
	level := audit.ParseLevel(config.AuditLevel)
	audit.SetLevel(level)
	log.Infof("Audit logging enabled: %s (level: %s)", auditDir, level)
}

func loadAuthPolicy() {
	if auth.DangerouslyAllowRoot() {
		log.Warn("WARNING: dangerously_allow_root is enabled — ALL auth checks are bypassed. Do not use in production!")
	}

	if err := auth.LoadPolicy(); err != nil {
		log.Errorf("Failed to load auth policy: %v", err)
	} else {
		roles := auth.ListRoles()
		users := auth.ListAllUsers()
		log.Infof("Auth policy loaded: %d role(s), %d user(s)", len(roles), len(users))
	}
}

func loadCohortRegistry() {
	registry, err := rbac.LoadCohortsFromConfig()
	if err != nil {
		log.Errorf("Failed to load cohort config: %v", err)
		registry = rbac.NewRegistry()
	}
	if err := registry.ValidateReferences(); err != nil {
		log.Errorf("Cohort reference validation failed: %v", err)
	}
	natsapi.SetCohortRegistry(registry)
	names := registry.List()
	if len(names) > 0 {
		log.Infof("Loaded %d cohort(s): %v", len(names), names)
	}
}

func createConfigRoot() {
	ConfigRoot := config.ConfigRoot
	_, err := os.Stat(ConfigRoot)
	if err == nil {
		return
	}
	if os.IsNotExist(err) {
		err = os.MkdirAll(ConfigRoot, os.ModePerm)
		if err != nil {
			log.Panicf("failed to create config directory: %v", err)
		}
	} else {

		log.Panicf("unexpected error checking config directory: %v", err)
	}
}

// StartAPIServer starts the farmer's HTTPS server. It handles PKI
// bootstrap (certificate distribution and NKey registration), file
// serving for recipe downloads (farmer:// scheme), and a health
// endpoint for monitoring and automated tooling.
func StartAPIServer() {
	CertFile := config.CertFile
	FarmerInterface := config.FarmerInterface
	FarmerAPIPort := config.FarmerAPIPort
	KeyFile := config.KeyFile
	r := api.NewRouter(CertFile)
	srv := &http.Server{
		Addr:         FarmerInterface + ":" + FarmerAPIPort,
		WriteTimeout: config.APIWriteTimeout,
		ReadTimeout:  config.APIReadTimeout,
		IdleTimeout:  config.APIIdleTimeout,
		Handler:      r,
	}
	setAPIServer(srv)
	go func() {
		if err := srv.ListenAndServeTLS(CertFile, KeyFile); err != nil && err != http.ErrServerClosed {
			log.Fatalf("API server failed: %v", err)
		}
	}()

	log.Tracef("API server started on %s\n", FarmerInterface+":"+FarmerAPIPort)
}

// handleSIGHUP listens for SIGHUP signals and reloads the API server
// and NATS server configuration. This allows certificate rotation and
// configuration changes to take effect without a full restart.
func handleSIGHUP(ctx context.Context, done chan<- struct{}) {
	defer close(done)
	sighup := make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)
	defer signal.Stop(sighup)
	for {
		select {
		case <-ctx.Done():
			return
		case <-sighup:
		}
		// Re-check cancellation: the select above may have chosen the sighup
		// case even though shutdown was also requested. Don't start a new
		// server if we're shutting down.
		if ctx.Err() != nil {
			return
		}
		log.Info("Received SIGHUP, reloading servers...")

		// Reload NATS server NKeys (picks up new sprout keys, config changes)
		if err := pki.ReloadNKeys(); err != nil {
			log.Errorf("Failed to reload NKeys: %v", err)
		} else {
			log.Info("NATS NKeys reloaded successfully")
		}

		// Reload the NATS server configuration
		if srv := getNATSServer(); srv != nil {
			if err := srv.Reload(); err != nil {
				log.Errorf("Failed to reload NATS server: %v", err)
			} else {
				log.Info("NATS server reloaded successfully")
			}
		}

		// Gracefully shut down the API server and restart it
		// so it picks up any new TLS certificates
		if srv := getAPIServer(); srv != nil {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			if err := srv.Shutdown(shutdownCtx); err != nil {
				log.Errorf("Failed to gracefully shut down API server: %v", err)
			}
			cancel()
			log.Info("API server shut down, restarting...")
		}

		// Reload config before restarting the API server
		config.LoadConfig("farmer")
		props.ClearStaticProps()
		props.LoadStaticProps(config.StaticProps())
		loadCohortRegistry()
		loadAuthPolicy()
		// Don't restart the API server if shutdown was requested while we
		// were reloading.
		if ctx.Err() != nil {
			return
		}
		StartAPIServer()
		log.Info("Servers reloaded successfully")
	}
}

// RunNATSServer starts a new Go routine based server
func RunNATSServer() {
	// Optionally override for individual debugging of tests
	// err := opts.ProcessConfigFile("config.json")
	// if err != nil {
	//		log.Panicf("Error configuring server: %v", err)
	//	}
	var err error
	// The bus isn't listening yet at this point, so a resolver push here is
	// expected to fail in the common case; this call's real purpose is to
	// sync local JWT/PKI state so ConfigureNats seeds the resolver with an
	// up-to-date tenant Account JWT below. Not actionable, so log it quietly
	// and keep starting the bus regardless.
	if err := pki.ReloadNKeys(); err != nil {
		log.Debugf("NKey reload before NATS server start (push to not-yet-running bus expected to fail): %v", err)
	}
	opts := pki.ConfigureNats()
	srv, err := nats_server.NewServer(&opts)
	if err != nil || srv == nil {
		log.Panicf("No NATS Server object returned: %v", err)
	}
	// Run server in Go routine.
	go srv.Start()
	var natsLogger log.Logger
	srv.SetLogger(natsLogger, true, true)
	// Wait for accept loop(s) to be started
	if !srv.ReadyForConnections(10 * time.Second) {
		log.Panicf("Unable to start NATS Server")
	}
	setNATSServer(srv)
	pki.SetNATSServer(srv)
	// The bus is up and reachable now, so a push failure here is a real,
	// actionable problem (same class as the SIGHUP handler's reload below).
	// Don't panic over it though: a later SIGHUP or Accept/Deny call can
	// still push successfully, so this must be visible but not fatal.
	if err := pki.ReloadNKeys(); err != nil {
		log.Errorf("Failed to reload NKeys after starting NATS server: %v", err)
	}
}

func ConnectFarmer(ctx context.Context, done chan<- struct{}) {
	defer close(done)
	var connectionAttempts atomic.Int64
	connectionAttempts.Store(1)
	maxFarmerReconnect := 30
	RootCA := config.RootCA
	BusURL := config.FarmerBusURL
	FarmerInterface := config.FarmerInterface
	if FarmerInterface == "0.0.0.0" {
		FarmerInterface = "localhost"
	}
	var err error
	opt, err := nats.NkeyOptionFromSeed(config.NKeyFarmerPrivFile)

	if err != nil {
		// NKey seed is critical for NATS authentication
		log.Panic(err)
	}
	certPool := x509.NewCertPool()
	rootPEM, err := os.ReadFile(RootCA)
	if err != nil || rootPEM == nil {
		log.Panicf("nats: error loading or parsing rootCA file: %v", err)
	}
	ok := certPool.AppendCertsFromPEM(rootPEM)
	if !ok {
		log.Errorf("nats: failed to parse root certificate from %v", RootCA)
	}

	tlsCfg := &tls.Config{
		ServerName: FarmerInterface,
		RootCAs:    certPool,
		MinVersion: tls.VersionTLS12,
	}
	log.Debug("Attempting to pair Farmer to NATS bus.")
	nc, err := nats.Connect(BusURL,
		nats.Secure(tlsCfg),
		opt,
		nats.RetryOnFailedConnect(true),
		nats.MaxReconnects(maxFarmerReconnect),
		nats.ReconnectWait(time.Second*15),
		nats.DisconnectHandler(func(_ *nats.Conn) {
			log.Warnf("WARN: Reconnecting Farmer to NATS bus, attempt: %d\n", connectionAttempts.Add(1))
		}),
	)
	if err != nil {
		log.Errorf("Got an error on Connect with Secure Options: %+v\n", err)
	}
	if nc == nil {
		log.Fatalf("Failed to connect Farmer to NATS bus: %v", err)
	}
	for !nc.IsConnected() {
		attempts := connectionAttempts.Add(1)
		log.Debugf("Attempting to pair Farmer to NATS bus (attempt %d/%d).", attempts, maxFarmerReconnect)
		if attempts >= int64(maxFarmerReconnect) {
			log.Fatalf("Failed to connect Farmer to NATS %d times, exiting.", attempts)
		}
		select {
		case <-ctx.Done():
			nc.Close()
			return
		case <-time.After(time.Second * 15):
		}
	}
	connectionAttempts.Store(0)
	log.Debugf("Successfully joined Farmer to NATS bus")

	if err := log.ConnectNATS(BusURL); err != nil {
		log.Errorf("Failed to connect log-nats backend: %v", err)
	}

	_, err = nc.Subscribe("grlx.sprouts.announce.>", func(m *nats.Msg) {
		log.Infof("Received a join event: %s\n", string(m.Data))
	})
	if err != nil {
		log.Errorf("Got an error on Subscribe: %+v\n", err)
	}

	test.RegisterNatsConn(nc)
	cmd.RegisterNatsConn(nc)
	cook.RegisterNatsConn(nc)
	jobs.RegisterNatsConn(nc)
	facts.RegisterFarmerListener(nc)

	// Set version info and subscribe NATS API handlers.
	natsapi.SetBuildVersion(config.Version{
		Arch:      runtime.GOOS,
		Compiler:  runtime.Version(),
		GitCommit: GitCommit,
		Tag:       Tag,
	})
	if err := natsapi.Subscribe(nc); err != nil {
		log.Errorf("Failed to subscribe NATS API handlers: %v", err)
	} else {
		log.Info("NATS API handlers registered")
	}
	// Start the job log reaper to clean up old job files.
	jobStore := jobs.NewStore()
	jobStore.StartReaperCtx(ctx, config.JobLogTTL)
	<-ctx.Done()
	nc.Close()
}
