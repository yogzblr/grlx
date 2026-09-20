package heartbeat

// These tests cover this package's own logic (tenant/key scoping, and
// mapping a CONNECT/DISCONNECT event to a sprout ID) against an in-memory
// PKI store. They deliberately don't exercise a real Set/Del/Exists round
// trip: valkey-go's command builder needs an unexported "no keyslot
// restriction" sentinel to build a valid command outside of an actual
// client connection, and its ValkeyMessage success-reply type has no
// exported constructor either — both are internal to that package, so a
// faithful fake isn't buildable from here without a live Valkey/Redis
// server (e.g. in a docker-compose-backed integration test), which this
// unit test suite doesn't have. IsOnline/handleConnect/handleDisconnect's
// nil-client short-circuit (exercised below) is what every code path
// actually goes through when no Valkey backend is configured, which is
// worth covering directly.

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/gogrlx/grlx/v2/internal/config"
	"github.com/gogrlx/grlx/v2/internal/pki"
)

// newTestPKIDB wires up an in-memory PKI store, plus the minimal config
// pki.ReloadNKeys (called via defer by AcceptNKey/UnacceptNKey) needs to
// fail fast rather than fatally — a dummy farmer pub key file so it
// doesn't log.Fatalf, matching internal/pki's own test setup.
func newTestPKIDB(t *testing.T) {
	t.Helper()
	dsn := "file:" + t.Name() + "-pki?mode=memory&cache=shared"
	gdb, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("opening pki test db: %v", err)
	}
	if err := gdb.AutoMigrate(pki.Models()...); err != nil {
		t.Fatalf("migrating pki test db: %v", err)
	}
	pki.SetDB(gdb)
	t.Cleanup(func() { pki.SetDB(nil) })

	dir := t.TempDir()
	config.FarmerPKI = dir + "/"
	farmerPubFile := filepath.Join(dir, "farmer.pub")
	if err := os.WriteFile(farmerPubFile, []byte("UFAKE_FARMER_KEY_FOR_TESTING"), 0o600); err != nil {
		t.Fatal(err)
	}
	config.NKeyFarmerPubFile = farmerPubFile
	pki.NatsServer = nil
}

func TestTenantIDDefault(t *testing.T) {
	old := config.FarmerOrganization
	defer func() { config.FarmerOrganization = old }()

	config.FarmerOrganization = ""
	if got := tenantID(); got != "default" {
		t.Errorf("tenantID() = %q, want %q", got, "default")
	}

	config.FarmerOrganization = "acme"
	if got := tenantID(); got != "acme" {
		t.Errorf("tenantID() = %q, want %q", got, "acme")
	}
}

func TestKeyFor(t *testing.T) {
	got := keyFor("acme", "sprout-1")
	want := "grlx:heartbeat:acme:sprout-1"
	if got != want {
		t.Errorf("keyFor() = %q, want %q", got, want)
	}
}

func TestIsOnline_NilClient(t *testing.T) {
	SetClient(nil)
	if IsOnline(context.Background(), "any-sprout") {
		t.Error("expected false with no client configured")
	}
}

func TestSproutIDFromEvent_MalformedJSON(t *testing.T) {
	newTestPKIDB(t)

	if _, ok := sproutIDFromEvent([]byte("{not json"), "CONNECT"); ok {
		t.Error("expected ok=false for malformed event JSON")
	}
}

func TestSproutIDFromEvent_UnknownPubkey(t *testing.T) {
	newTestPKIDB(t)

	data := []byte(`{"client":{"user":"UNKNOWN_PUBKEY"}}`)
	if _, ok := sproutIDFromEvent(data, "CONNECT"); ok {
		t.Error("expected ok=false for a pubkey with no accepted sprout")
	}
}

func TestSproutIDFromEvent_AcceptedSprout(t *testing.T) {
	newTestPKIDB(t)

	if err := pki.UnacceptNKey("web-01", "UPUBKEY123"); err != nil {
		t.Fatalf("UnacceptNKey: %v", err)
	}
	if err := pki.AcceptNKey("web-01"); err != nil {
		t.Fatalf("AcceptNKey: %v", err)
	}

	data := []byte(`{"client":{"user":"UPUBKEY123"}}`)
	sproutID, ok := sproutIDFromEvent(data, "CONNECT")
	if !ok {
		t.Fatal("expected ok=true for an accepted sprout's pubkey")
	}
	if sproutID != "web-01" {
		t.Errorf("sproutID = %q, want %q", sproutID, "web-01")
	}
}

func TestSproutIDFromEvent_UnacceptedSproutNotOnline(t *testing.T) {
	newTestPKIDB(t)

	if err := pki.UnacceptNKey("web-02", "UPUBKEY456"); err != nil {
		t.Fatalf("UnacceptNKey: %v", err)
	}

	data := []byte(`{"client":{"user":"UPUBKEY456"}}`)
	if _, ok := sproutIDFromEvent(data, "CONNECT"); ok {
		t.Error("expected ok=false for a sprout that isn't accepted yet")
	}
}

func TestHandleConnectDisconnect_NilClientDoesNotPanic(t *testing.T) {
	newTestPKIDB(t)
	SetClient(nil)

	if err := pki.UnacceptNKey("web-03", "UPUBKEY789"); err != nil {
		t.Fatalf("UnacceptNKey: %v", err)
	}
	if err := pki.AcceptNKey("web-03"); err != nil {
		t.Fatalf("AcceptNKey: %v", err)
	}

	data := []byte(`{"client":{"user":"UPUBKEY789"}}`)
	handleConnect(data)
	handleDisconnect(data)
}
