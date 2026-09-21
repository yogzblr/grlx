package pki

import (
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"
)

func testBoxPub(t *testing.T) string {
	t.Helper()
	var pub [32]byte
	if _, err := rand.Read(pub[:]); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return base64.StdEncoding.EncodeToString(pub[:])
}

func TestDecodeBoxPub(t *testing.T) {
	valid := testBoxPub(t)
	if _, err := decodeBoxPub(valid); err != nil {
		t.Errorf("expected valid pub to decode, got %v", err)
	}

	for _, bad := range []string{"", "not-base64!!!", base64.StdEncoding.EncodeToString([]byte("short"))} {
		if _, err := decodeBoxPub(bad); err == nil {
			t.Errorf("expected an error decoding %q", bad)
		}
	}
}

func TestValidSproutBoxKeys_NoneEnrolled(t *testing.T) {
	setupTestPKI(t)

	if _, _, err := ValidSproutBoxKeys("nobody"); err != ErrNoActiveBoxKey {
		t.Fatalf("expected ErrNoActiveBoxKey, got %v", err)
	}
}

func TestUpsertSproutBoxKeyActive_IdempotentSamePub(t *testing.T) {
	setupTestPKI(t)
	pub := testBoxPub(t)

	if err := upsertSproutBoxKeyActive(tenantID(), "web-01", pub); err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	if err := upsertSproutBoxKeyActive(tenantID(), "web-01", pub); err != nil {
		t.Fatalf("second upsert: %v", err)
	}

	active, grace, err := ValidSproutBoxKeys("web-01")
	if err != nil {
		t.Fatalf("ValidSproutBoxKeys: %v", err)
	}
	if active != pub {
		t.Errorf("expected active %q, got %q", pub, active)
	}
	if len(grace) != 0 {
		t.Errorf("expected no grace keys, got %v", grace)
	}
}

func TestUpsertSproutBoxKeyActive_RejectsMalformedPub(t *testing.T) {
	setupTestPKI(t)
	if err := upsertSproutBoxKeyActive(tenantID(), "web-01", "not-valid"); err == nil {
		t.Fatal("expected an error for a malformed pub")
	}
}

func TestRotateSproutBoxKey_GracesThePreviousKey(t *testing.T) {
	setupTestPKI(t)
	oldPub := testBoxPub(t)
	newPub := testBoxPub(t)

	if err := upsertSproutBoxKeyActive(tenantID(), "web-01", oldPub); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := RotateSproutBoxKey("web-01", newPub, time.Hour); err != nil {
		t.Fatalf("RotateSproutBoxKey: %v", err)
	}

	active, grace, err := ValidSproutBoxKeys("web-01")
	if err != nil {
		t.Fatalf("ValidSproutBoxKeys: %v", err)
	}
	if active != newPub {
		t.Errorf("expected active %q, got %q", newPub, active)
	}
	if len(grace) != 1 || grace[0] != oldPub {
		t.Errorf("expected old pub %q in grace, got %v", oldPub, grace)
	}
}

func TestRotateSproutBoxKey_IdempotentWhenAlreadyActive(t *testing.T) {
	setupTestPKI(t)
	pub := testBoxPub(t)

	if err := upsertSproutBoxKeyActive(tenantID(), "web-01", pub); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	// Rotating to the pub that's already active must not grace it.
	if err := RotateSproutBoxKey("web-01", pub, time.Hour); err != nil {
		t.Fatalf("RotateSproutBoxKey: %v", err)
	}

	active, grace, err := ValidSproutBoxKeys("web-01")
	if err != nil {
		t.Fatalf("ValidSproutBoxKeys: %v", err)
	}
	if active != pub {
		t.Errorf("expected active %q, got %q", pub, active)
	}
	if len(grace) != 0 {
		t.Errorf("expected no grace keys, got %v", grace)
	}
}

func TestRotateSproutBoxKey_RejectsMalformedNewPub(t *testing.T) {
	setupTestPKI(t)
	if err := upsertSproutBoxKeyActive(tenantID(), "web-01", testBoxPub(t)); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := RotateSproutBoxKey("web-01", "not-valid", time.Hour); err == nil {
		t.Fatal("expected an error for a malformed new pub")
	}
}

func TestValidSproutBoxKeys_ExpiredGraceKeyExcludedAndSwept(t *testing.T) {
	setupTestPKI(t)
	oldPub := testBoxPub(t)
	newPub := testBoxPub(t)

	if err := upsertSproutBoxKeyActive(tenantID(), "web-01", oldPub); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	// A negative grace duration means the old key's grace window has
	// already closed by the time we ask.
	if err := RotateSproutBoxKey("web-01", newPub, -time.Hour); err != nil {
		t.Fatalf("RotateSproutBoxKey: %v", err)
	}

	active, grace, err := ValidSproutBoxKeys("web-01")
	if err != nil {
		t.Fatalf("ValidSproutBoxKeys: %v", err)
	}
	if active != newPub {
		t.Errorf("expected active %q, got %q", newPub, active)
	}
	if len(grace) != 0 {
		t.Errorf("expected expired grace key to be excluded, got %v", grace)
	}

	// Verify the sweep actually flipped the row's state, not just that the
	// query filtered it out.
	var row sproutBoxKeyRow
	if err := db.Where("tenant_id = ? AND sprout_id = ? AND pub = ?", tenantID(), "web-01", oldPub).
		First(&row).Error; err != nil {
		t.Fatalf("finding old key row: %v", err)
	}
	if row.State != boxKeyStateRevoked {
		t.Errorf("expected swept state %q, got %q", boxKeyStateRevoked, row.State)
	}
}

// A second rotation before the first one's grace window closes leaves both
// former keys valid, each on its own independent grace_until — nothing
// about a newer rotation shortens an older grace window early.
func TestRotateSproutBoxKey_MultipleRotationsOverlapIndependently(t *testing.T) {
	setupTestPKI(t)
	pub1 := testBoxPub(t)
	pub2 := testBoxPub(t)
	pub3 := testBoxPub(t)

	if err := upsertSproutBoxKeyActive(tenantID(), "web-01", pub1); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := RotateSproutBoxKey("web-01", pub2, time.Hour); err != nil {
		t.Fatalf("rotate 1: %v", err)
	}
	if err := RotateSproutBoxKey("web-01", pub3, time.Hour); err != nil {
		t.Fatalf("rotate 2: %v", err)
	}

	active, grace, err := ValidSproutBoxKeys("web-01")
	if err != nil {
		t.Fatalf("ValidSproutBoxKeys: %v", err)
	}
	if active != pub3 {
		t.Errorf("expected active %q, got %q", pub3, active)
	}
	graceSet := map[string]bool{}
	for _, g := range grace {
		graceSet[g] = true
	}
	if !graceSet[pub1] || !graceSet[pub2] || len(grace) != 2 {
		t.Errorf("expected both pub1 and pub2 in grace, got %v", grace)
	}
}
