package pki

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"strconv"

	log "github.com/gogrlx/grlx/v2/internal/log"

	"github.com/gogrlx/grlx/v2/internal/config"

	jwt "github.com/nats-io/jwt/v2"
	nats_server "github.com/nats-io/nats-server/v2/server"
)

var (
	NatsServer *nats_server.Server
	NatsOpts   *nats_server.Options
	cert       tls.Certificate
	certPool   *x509.CertPool
)

// ConfigureNats builds the NATS server options for this farmer's bus node.
// Auth is decentralized JWT (see docs/design/grlx-nats-jwt-auth-design.md):
// the Operator is the trust anchor, the SYSTEM account is used only to
// receive claims-update pushes (see resolver.go), and a "full" resolver
// (every node holds every Account JWT, appropriate at the near-term tenant
// count) is seeded with the SYSTEM and tenant Account JWTs so the server
// can validate connections from the moment it starts.
func ConfigureNats() nats_server.Options {
	var NatsConfig nats_server.Options
	FarmerInterface := config.FarmerInterface
	FBusPort := config.FarmerBusPort
	FarmerBusPort, err := strconv.Atoi(FBusPort)
	if err != nil {
		log.Panic(err)
	}
	RootCA := config.RootCA
	CertFile := config.CertFile
	KeyFile := config.KeyFile
	NatsConfig = nats_server.Options{
		Host:                  FarmerInterface,
		Port:                  FarmerBusPort,
		NoSigs:                true,
		MaxControlLine:        4096,
		DisableShortFirstPing: true,
		Trace:                 true,
		Debug:                 true,
		TLS:                   true,
		AllowNonTLS:           false,
		LogFile:               "nats.log",
		AuthTimeout:           10,
	}
	certPool = x509.NewCertPool()
	rootPEM, err := os.ReadFile(RootCA)
	if err != nil || rootPEM == nil {
		log.Panicf("nats: error loading or parsing rootCA file: %v", err)
	}
	ok := certPool.AppendCertsFromPEM(rootPEM)
	if !ok {
		log.Errorf("nats: failed to parse root certificate from %v", RootCA)
	}
	cert, err = tls.LoadX509KeyPair(CertFile, KeyFile)
	if err != nil {
		log.Panic(err)
	}
	tlsConfig := tls.Config{
		ServerName:   FarmerInterface,
		RootCAs:      certPool,
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	NatsConfig.TLSConfig = &tlsConfig

	// Websocket listener: what Envoy's jwt_authn-gated wss:// route
	// (docs/design/grlx-envoy-enrollment-design.md) terminates onto.
	// Reuses the same server certificate as the plain TCP listener above.
	// Auth here is still the ordinary decentralized JWT/NKey CONNECT-time
	// check (AccountResolver, set below) — Envoy's JWT validation happens
	// earlier, in front of this listener, not instead of it; see the
	// design doc's "two gates, checking different things, not redundant
	// with each other."
	//
	// FarmerWSPort defaults to "5407" via config.LoadConfig, but is left
	// unset by several existing tests that build config values directly
	// rather than loading them — treat that as "no websocket listener"
	// rather than failing the whole server start.
	if config.FarmerWSPort != "" {
		wsPort, err := strconv.Atoi(config.FarmerWSPort)
		if err != nil {
			log.Panic(err)
		}
		NatsConfig.Websocket = nats_server.WebsocketOpts{
			Host: FarmerInterface,
			Port: wsPort,
			TLSConfig: &tls.Config{
				ServerName:   FarmerInterface,
				RootCAs:      certPool,
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS12,
			},
			AuthTimeout: 10,
		}
	}

	mat, err := ensureNatsAuth()
	if err != nil {
		log.Panicf("nats: failed to bootstrap decentralized JWT auth material: %v", err)
	}
	opClaims, err := jwt.DecodeOperatorClaims(mat.operatorJWT)
	if err != nil {
		log.Panicf("nats: failed to decode operator JWT: %v", err)
	}
	NatsConfig.TrustedOperators = []*jwt.OperatorClaims{opClaims}
	NatsConfig.SystemAccount = mat.sysAccountPub

	resolver, err := nats_server.NewDirAccResolver(resolverStoreDir(), 0, 0, nats_server.HardDelete)
	if err != nil {
		log.Panicf("nats: failed to create the account resolver: %v", err)
	}
	if err := resolver.Store(mat.sysAccountPub, mat.sysAccountJWT); err != nil {
		log.Panicf("nats: failed to seed the SYS account into the resolver: %v", err)
	}
	if err := resolver.Store(mat.tenantPub, mat.tenantJWT); err != nil {
		log.Panicf("nats: failed to seed the tenant account into the resolver: %v", err)
	}
	NatsConfig.AccountResolver = resolver

	return NatsConfig
}

func SetNATSServer(s *nats_server.Server) {
	NatsServer = s
}

// ReloadNKeys recomputes the tenant Account's User JWTs and revocation list
// from the current accept/deny/reject/unaccept sprout state (see
// syncNatsAuth in jwtusers.go), and, if that changed the Account JWT,
// pushes the update to the resolver (see resolver.go).
//
// This replaces the old behavior of rebuilding an NkeyUser allow-list and
// calling NatsServer.ReloadOptions() in-process; the name is kept because
// pki.go's Accept/Deny/Reject/Unaccept/Delete all call it via defer, and
// cmd/farmer/main.go calls it directly on SIGHUP.
//
// The push (pushAccountUpdate -> connectSystemAccount) dials
// config.FarmerBusURL over the network as the SYS account; it does not
// depend on this process holding a local NatsServer handle, so the push is
// always attempted when changed is true, regardless of whether this
// process itself embeds the bus. That must stay true once farmer's bus and
// core processes are split into separate binaries (workstream C): the core
// process, where Accept/Deny/API calls happen, will never have a local
// NatsServer, but it still needs its pushes to reach the bus.
func ReloadNKeys() error {
	mat, err := ensureNatsAuth()
	if err != nil {
		log.Errorf("failed to bootstrap NATS decentralized-auth material: %v", err)
		return err
	}
	changed, err := syncNatsAuth(mat)
	if err != nil {
		log.Errorf("failed to sync the tenant Account JWT: %v", err)
		return err
	}
	if !changed {
		return nil
	}
	if err := pushAccountUpdate(mat); err != nil {
		log.Errorf("failed to push the updated Account JWT to the bus resolver: %v", err)
		return err
	}
	log.Tracef("Pushed updated tenant Account JWT to the bus resolver.")
	return nil
}
