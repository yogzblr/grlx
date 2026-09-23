package pki

// Live-bus proof of the SaaS API credential's scoping (FLAG FOR SECURITY
// REVIEW — see docs/design/grlx-internal-api-account.md). Asserting on the
// JWT's fields alone (saasapi_user_test.go) wouldn't prove that a User in
// the SYS Account really gets no $SYS reach beyond its own allow-lists;
// this does, against a real embedded nats-server.

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	nats "github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"

	"github.com/gogrlx/grlx/v2/internal/config"
)

// permissionErrors collects the asynchronous -ERR 'Permissions Violation'
// notices the server sends for a denied publish or subscribe.
type permissionErrors struct {
	mu   sync.Mutex
	errs []string
}

func (p *permissionErrors) handler(_ *nats.Conn, _ *nats.Subscription, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.errs = append(p.errs, err.Error())
}

// waitFor reports whether a permission violation naming subject arrives
// within a short window.
func (p *permissionErrors) waitFor(subject string) bool {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		p.mu.Lock()
		for _, e := range p.errs {
			if strings.Contains(e, "Permissions Violation") && strings.Contains(e, `"`+subject+`"`) {
				p.mu.Unlock()
				return true
			}
		}
		p.mu.Unlock()
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

func (p *permissionErrors) any() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.errs...)
}

func dialWithCreds(t *testing.T, userJWT string, seed []byte, opts ...nats.Option) (*nats.Conn, error) {
	t.Helper()
	rootPEM, err := os.ReadFile(config.RootCA)
	if err != nil {
		t.Fatalf("reading root CA: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(rootPEM) {
		t.Fatal("failed to parse root CA")
	}
	return nats.Connect(config.FarmerBusURL, append([]nats.Option{
		nats.Secure(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}),
		nats.UserJWTAndSeed(userJWT, string(seed)),
		nats.Timeout(5 * time.Second),
		nats.RetryOnFailedConnect(false),
		nats.NoReconnect(),
	}, opts...)...)
}

func TestSaaSAPICredential_ScopedOnLiveBus(t *testing.T) {
	setupTestPKI(t)
	defer startTestBus(t)()

	userJWT, seed, err := EnsureSaaSAPICredential()
	if err != nil {
		t.Fatalf("EnsureSaaSAPICredential: %v", err)
	}

	// Farmer's side: its SYS connection, the one internal/natsapi's
	// provisioning handlers are registered on.
	farmer, err := ConnectSystemAccount()
	if err != nil {
		t.Fatalf("ConnectSystemAccount: %v", err)
	}
	defer farmer.Close()
	requests, _ := farmer.SubscribeSync("internal.tenant.provision")
	forged, _ := farmer.SubscribeSync("internal.tenant.provisioned.pj_forged")
	grlxAPI, _ := farmer.SubscribeSync("grlx.api.>")
	if err := farmer.Flush(); err != nil {
		t.Fatalf("farmer flush: %v", err)
	}

	var perrs permissionErrors
	saas, err := dialWithCreds(t, userJWT, seed, nats.ErrorHandler(perrs.handler))
	if err != nil {
		t.Fatalf("expected the SaaS API credential to connect: %v", err)
	}
	defer saas.Close()

	// Allowed: subscribe to results, publish a request that farmer receives.
	results, err := saas.SubscribeSync("internal.tenant.provisioned.*")
	if err != nil {
		t.Fatalf("subscribe to results: %v", err)
	}
	if err := saas.Publish("internal.tenant.provision", []byte(`{}`)); err != nil {
		t.Fatalf("publish request: %v", err)
	}
	if err := saas.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if _, err := requests.NextMsg(2 * time.Second); err != nil {
		t.Fatalf("expected farmer's SYS connection to receive the SaaS API's request: %v", err)
	}
	if err := farmer.Publish("internal.tenant.provisioned.pj_1", []byte(`{}`)); err != nil {
		t.Fatalf("farmer publish result: %v", err)
	}
	if _, err := results.NextMsg(2 * time.Second); err != nil {
		t.Fatalf("expected the SaaS API to receive farmer's result: %v", err)
	}
	if got := perrs.any(); len(got) != 0 {
		t.Fatalf("unexpected permission errors on allowed operations: %v", got)
	}

	// Denied publishes: $SYS administration, a tenant API subject, and a
	// forged result (only farmer may publish those).
	for _, subj := range []string{
		"$SYS.REQ.SERVER.PING",
		"$SYS.REQ.ACCOUNT.PING.CONNZ",
		"$SYS.REQ.CLAIMS.UPDATE",
		"grlx.api.health",
		"grlx.sprouts.web-01.cmd.run",
		"internal.tenant.provisioned.pj_forged",
	} {
		_ = saas.Publish(subj, []byte(`{}`))
		_ = saas.Flush()
		if !perrs.waitFor(subj) {
			t.Errorf("expected publish to %q to be denied", subj)
		}
	}
	if _, err := forged.NextMsg(200 * time.Millisecond); err == nil {
		t.Error("a forged result from the SaaS API credential reached farmer's subscriber")
	}
	if _, err := grlxAPI.NextMsg(200 * time.Millisecond); err == nil {
		t.Error("a grlx.api publish from the SaaS API credential was delivered")
	}

	// Denied subscribes: farmer's own request subject, cross-tenant
	// connection events, $SYS generally, and any tenant's traffic.
	for _, subj := range []string{
		"internal.tenant.provision",
		"$SYS.ACCOUNT.*.CONNECT",
		"$SYS.>",
		"grlx.>",
		"_INBOX.>",
		">",
	} {
		if _, err := saas.SubscribeSync(subj); err != nil {
			t.Fatalf("SubscribeSync(%q) returned a local error: %v", subj, err)
		}
		_ = saas.Flush()
		if !perrs.waitFor(subj) {
			t.Errorf("expected subscribe to %q to be denied", subj)
		}
	}
}

// TestSaaSAPICredential_RotationRevokesPreviousKeyOnLiveBus proves that
// rotating the SaaS API's seed (a new GRLX_NATS_SAASAPI_USER_SEED from
// OpenBao) actually cuts off the old credential at the bus, via a
// revocation pushed on the SYS Account JWT — not just that a new JWT gets
// written locally.
func TestSaaSAPICredential_RotationRevokesPreviousKeyOnLiveBus(t *testing.T) {
	setupTestPKI(t)
	defer startTestBus(t)()

	oldKP, _ := nkeys.CreateUser()
	oldSeed, _ := oldKP.Seed()
	t.Setenv("GRLX_NATS_SAASAPI_USER_SEED", string(oldSeed))
	oldJWT, _, err := EnsureSaaSAPICredential()
	if err != nil {
		t.Fatalf("EnsureSaaSAPICredential (old key): %v", err)
	}
	nc, err := dialWithCreds(t, oldJWT, oldSeed)
	if err != nil {
		t.Fatalf("expected the original credential to connect: %v", err)
	}
	nc.Close()

	newKP, _ := nkeys.CreateUser()
	newSeed, _ := newKP.Seed()
	t.Setenv("GRLX_NATS_SAASAPI_USER_SEED", string(newSeed))
	newJWT, _, err := EnsureSaaSAPICredential()
	if err != nil {
		t.Fatalf("EnsureSaaSAPICredential (rotated key): %v", err)
	}
	if newJWT == oldJWT {
		t.Fatal("expected a new JWT for the rotated key")
	}

	if nc, err := dialWithCreds(t, oldJWT, oldSeed); err == nil {
		nc.Close()
		t.Fatal("expected the rotated-out credential to be rejected by the bus")
	}
	nc, err = dialWithCreds(t, newJWT, newSeed)
	if err != nil {
		t.Fatalf("expected the rotated-in credential to connect: %v", err)
	}
	nc.Close()

	// Farmer's own SYS push user must be unaffected by the revocation.
	sys, err := ConnectSystemAccount()
	if err != nil {
		t.Fatalf("expected farmer's SYS user to still connect after the SYS Account was re-signed: %v", err)
	}
	sys.Close()

	// A later boot with the same (new) key is a no-op mint but still
	// re-pushes the SYS Account JWT, since it carries a revocation.
	again, _, err := EnsureSaaSAPICredential()
	if err != nil {
		t.Fatalf("EnsureSaaSAPICredential (idempotent re-run): %v", err)
	}
	if again != newJWT {
		t.Fatal("expected the re-run to reuse the rotated-in JWT")
	}
}
