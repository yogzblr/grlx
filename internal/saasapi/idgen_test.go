package saasapi

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestNewID(t *testing.T) {
	a, err := newID("t_")
	if err != nil {
		t.Fatalf("newID: %v", err)
	}
	b, err := newID("t_")
	if err != nil {
		t.Fatalf("newID: %v", err)
	}
	if !strings.HasPrefix(a, "t_") || !strings.HasPrefix(b, "t_") {
		t.Fatalf("expected t_ prefix, got %q and %q", a, b)
	}
	if a == b {
		t.Fatalf("expected two distinct random ids, got the same value twice: %q", a)
	}
	if strings.ToLower(a) != a {
		t.Fatalf("expected lowercase id, got %q", a)
	}
}

func TestNewEnrollmentSecret(t *testing.T) {
	a, err := newEnrollmentSecret()
	if err != nil {
		t.Fatalf("newEnrollmentSecret: %v", err)
	}
	b, err := newEnrollmentSecret()
	if err != nil {
		t.Fatalf("newEnrollmentSecret: %v", err)
	}
	if a == b {
		t.Fatalf("expected two distinct random secrets, got the same value twice")
	}
	// base64.RawURLEncoding of 32 bytes must not contain padding or
	// characters that would need URL-escaping.
	if strings.ContainsAny(a, "=+/") {
		t.Fatalf("secret contains non-URL-safe characters: %q", a)
	}
}

func TestHashSecret(t *testing.T) {
	secret := "some-secret-value"
	got := hashSecret(secret)

	want := sha256.Sum256([]byte(secret))
	wantHex := hex.EncodeToString(want[:])

	if got != wantHex {
		t.Fatalf("hashSecret(%q) = %q, want %q", secret, got, wantHex)
	}
	if got == secret {
		t.Fatalf("hashSecret must not return the raw secret")
	}

	other := hashSecret("a-different-secret")
	if other == got {
		t.Fatalf("expected different secrets to hash differently")
	}
}
