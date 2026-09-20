package pki

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gogrlx/grlx/v2/internal/config"
)

func setupTenantBoxDir(t *testing.T) {
	t.Helper()
	config.FarmerPKI = t.TempDir() + "/"
	resetTenantX25519KeypairCache()
	t.Cleanup(resetTenantX25519KeypairCache)
}

func TestGetTenantX25519PublicKey_GeneratesAndPersists(t *testing.T) {
	setupTenantBoxDir(t)

	pub1, err := GetTenantX25519PublicKey()
	if err != nil {
		t.Fatalf("GetTenantX25519PublicKey: %v", err)
	}
	if pub1 == "" {
		t.Fatal("expected non-empty public key")
	}

	if _, err := os.Stat(tenantX25519PrivPath()); err != nil {
		t.Errorf("expected private key file to be written: %v", err)
	}
	info, err := os.Stat(tenantX25519PrivPath())
	if err != nil {
		t.Fatalf("stat private key: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("expected private key file mode 0600, got %o", perm)
	}

	// A second call, with the cache cleared, must load the same keypair
	// back from disk rather than generating a new one.
	resetTenantX25519KeypairCache()
	pub2, err := GetTenantX25519PublicKey()
	if err != nil {
		t.Fatalf("GetTenantX25519PublicKey (reload): %v", err)
	}
	if pub1 != pub2 {
		t.Errorf("expected stable public key across reload, got %q then %q", pub1, pub2)
	}
}

func TestGetTenantX25519PublicKey_CachedWithoutDiskRoundtrip(t *testing.T) {
	setupTenantBoxDir(t)

	pub1, err := GetTenantX25519PublicKey()
	if err != nil {
		t.Fatalf("GetTenantX25519PublicKey: %v", err)
	}

	// Remove the files without clearing the in-process cache: a cached
	// call must still succeed and return the same key.
	os.Remove(tenantX25519PrivPath())
	os.Remove(tenantX25519PubPath())

	pub2, err := GetTenantX25519PublicKey()
	if err != nil {
		t.Fatalf("GetTenantX25519PublicKey (cached): %v", err)
	}
	if pub1 != pub2 {
		t.Errorf("expected cached call to return the same key, got %q then %q", pub1, pub2)
	}
}

func TestGetTenantX25519PublicKey_CorruptFileErrors(t *testing.T) {
	setupTenantBoxDir(t)

	dir := filepath.Dir(tenantX25519PrivPath())
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(tenantX25519PrivPath(), []byte("short"), 0o600); err != nil {
		t.Fatalf("write bad priv file: %v", err)
	}
	if err := os.WriteFile(tenantX25519PubPath(), make([]byte, 32), 0o644); err != nil {
		t.Fatalf("write pub file: %v", err)
	}

	if _, err := GetTenantX25519PublicKey(); err == nil {
		t.Fatal("expected an error for a truncated private key file")
	}
}
