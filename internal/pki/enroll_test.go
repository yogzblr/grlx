package pki

import (
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/nats-io/nkeys"
)

// fakeEnrollmentKeyStore is an in-memory stand-in for mysqlEnrollmentKeyStore
// (see enroll.go's doc comment on enrollmentKeyStore for why: this
// package's tests run against SQLite, which can't execute the production
// store's MySQL-specific cross-schema raw SQL).
type fakeEnrollmentKeyStore struct {
	rows map[string]*enrollmentKeyRow
}

func newFakeEnrollmentKeyStore() *fakeEnrollmentKeyStore {
	return &fakeEnrollmentKeyStore{rows: map[string]*enrollmentKeyRow{}}
}

func (f *fakeEnrollmentKeyStore) lookup(keyID string) (*enrollmentKeyRow, error) {
	row, ok := f.rows[keyID]
	if !ok {
		return nil, sql.ErrNoRows
	}
	cp := *row
	return &cp, nil
}

// redeem mirrors the production UPDATE ... WHERE guard (enroll.go's
// mysqlEnrollmentKeyStore.redeem): it only increments used_count when the
// same conditions that WHERE clause checks all still hold.
func (f *fakeEnrollmentKeyStore) redeem(keyID string) (bool, error) {
	row, ok := f.rows[keyID]
	if !ok {
		return false, nil
	}
	if row.Revoked || row.UsedCount >= row.MaxUses || time.Now().UTC().After(row.Expiry) {
		return false, nil
	}
	row.UsedCount++
	return true, nil
}

func withFakeEnrollmentKeyStore(t *testing.T, f *fakeEnrollmentKeyStore) {
	t.Helper()
	orig := enrollKeyStore
	enrollKeyStore = f
	t.Cleanup(func() { enrollKeyStore = orig })
}

func testEnrollNKey(t *testing.T) string {
	t.Helper()
	kp, err := nkeys.CreateUser()
	if err != nil {
		t.Fatalf("create nkey: %v", err)
	}
	pub, err := kp.PublicKey()
	if err != nil {
		t.Fatalf("pubkey: %v", err)
	}
	return pub
}

func TestEnroll_Success(t *testing.T) {
	setupTestPKI(t)
	store := newFakeEnrollmentKeyStore()
	store.rows["ek_1"] = &enrollmentKeyRow{
		TenantID: "t_1", KeyHash: hashSecret("supersecret"),
		Expiry: time.Now().Add(time.Hour), MaxUses: 5, UsedCount: 0,
	}
	withFakeEnrollmentKeyStore(t, store)

	nkeyPub := testEnrollNKey(t)
	result, err := Enroll("ek_1.supersecret", nkeyPub, "web-01")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if result.SproutID != "web-01" {
		t.Errorf("expected sprout id web-01, got %s", result.SproutID)
	}
	if result.JWT == "" {
		t.Error("expected non-empty JWT")
	}
	if result.TenantX25519Pub == "" {
		t.Error("expected non-empty tenant X25519 pubkey")
	}
	if store.rows["ek_1"].UsedCount != 1 {
		t.Errorf("expected used_count 1, got %d", store.rows["ek_1"].UsedCount)
	}

	sproutID, err := SproutIDForNKey(nkeyPub)
	if err != nil || sproutID != "web-01" {
		t.Errorf("expected sprout accepted under web-01, got %q err=%v", sproutID, err)
	}
}

func TestEnroll_IdempotentReplayDoesNotConsumeToken(t *testing.T) {
	setupTestPKI(t)
	store := newFakeEnrollmentKeyStore()
	store.rows["ek_1"] = &enrollmentKeyRow{KeyHash: hashSecret("supersecret"), Expiry: time.Now().Add(time.Hour), MaxUses: 1}
	withFakeEnrollmentKeyStore(t, store)

	nkeyPub := testEnrollNKey(t)
	first, err := Enroll("ek_1.supersecret", nkeyPub, "web-01")
	if err != nil {
		t.Fatalf("first Enroll: %v", err)
	}

	// Retry with the same nkey_pub but a bogus token: design doc §3.3 step
	// 1 says the idempotency check happens before the token is even
	// looked at, so this should replay the existing identity.
	second, err := Enroll("bogus.token", nkeyPub, "web-01")
	if err != nil {
		t.Fatalf("replay Enroll: %v", err)
	}
	if second.JWT != first.JWT || second.SproutID != first.SproutID {
		t.Errorf("expected replay to return identical identity, got %+v vs %+v", first, second)
	}
	if store.rows["ek_1"].UsedCount != 1 {
		t.Errorf("expected replay not to consume a use, used_count=%d", store.rows["ek_1"].UsedCount)
	}
}

func TestEnroll_UnknownKeyID(t *testing.T) {
	setupTestPKI(t)
	withFakeEnrollmentKeyStore(t, newFakeEnrollmentKeyStore())

	if _, err := Enroll("nope.secret", testEnrollNKey(t), "web-01"); !errors.Is(err, ErrEnrollmentFailed) {
		t.Fatalf("expected ErrEnrollmentFailed, got %v", err)
	}
}

func TestEnroll_WrongSecret(t *testing.T) {
	setupTestPKI(t)
	store := newFakeEnrollmentKeyStore()
	store.rows["ek_1"] = &enrollmentKeyRow{KeyHash: hashSecret("real"), Expiry: time.Now().Add(time.Hour), MaxUses: 1}
	withFakeEnrollmentKeyStore(t, store)

	if _, err := Enroll("ek_1.wrong", testEnrollNKey(t), "web-01"); !errors.Is(err, ErrEnrollmentFailed) {
		t.Fatalf("expected ErrEnrollmentFailed, got %v", err)
	}
	if store.rows["ek_1"].UsedCount != 0 {
		t.Error("expected wrong secret not to redeem a use")
	}
}

func TestEnroll_Revoked(t *testing.T) {
	setupTestPKI(t)
	store := newFakeEnrollmentKeyStore()
	store.rows["ek_1"] = &enrollmentKeyRow{KeyHash: hashSecret("s"), Expiry: time.Now().Add(time.Hour), MaxUses: 1, Revoked: true}
	withFakeEnrollmentKeyStore(t, store)

	if _, err := Enroll("ek_1.s", testEnrollNKey(t), "web-01"); !errors.Is(err, ErrEnrollmentFailed) {
		t.Fatalf("expected ErrEnrollmentFailed, got %v", err)
	}
}

func TestEnroll_Expired(t *testing.T) {
	setupTestPKI(t)
	store := newFakeEnrollmentKeyStore()
	store.rows["ek_1"] = &enrollmentKeyRow{KeyHash: hashSecret("s"), Expiry: time.Now().Add(-time.Hour), MaxUses: 1}
	withFakeEnrollmentKeyStore(t, store)

	if _, err := Enroll("ek_1.s", testEnrollNKey(t), "web-01"); !errors.Is(err, ErrEnrollmentFailed) {
		t.Fatalf("expected ErrEnrollmentFailed, got %v", err)
	}
}

func TestEnroll_ExhaustedByPriorRedemption(t *testing.T) {
	setupTestPKI(t)
	store := newFakeEnrollmentKeyStore()
	store.rows["ek_1"] = &enrollmentKeyRow{KeyHash: hashSecret("s"), Expiry: time.Now().Add(time.Hour), MaxUses: 1}
	withFakeEnrollmentKeyStore(t, store)

	if _, err := Enroll("ek_1.s", testEnrollNKey(t), "web-01"); err != nil {
		t.Fatalf("first enroll: %v", err)
	}
	// A second, different sprout (so idempotency doesn't short-circuit)
	// presenting the same now-exhausted token must fail.
	if _, err := Enroll("ek_1.s", testEnrollNKey(t), "web-02"); !errors.Is(err, ErrEnrollmentFailed) {
		t.Fatalf("expected second redemption to fail, got %v", err)
	}
}

func TestEnroll_MalformedToken(t *testing.T) {
	setupTestPKI(t)
	withFakeEnrollmentKeyStore(t, newFakeEnrollmentKeyStore())

	for _, tok := range []string{"", "nodot", ".nokeyid", "keyid."} {
		if _, err := Enroll(tok, testEnrollNKey(t), "web-01"); !errors.Is(err, ErrEnrollmentFailed) {
			t.Errorf("token %q: expected ErrEnrollmentFailed, got %v", tok, err)
		}
	}
}

func TestEnroll_InvalidNKey(t *testing.T) {
	setupTestPKI(t)
	withFakeEnrollmentKeyStore(t, newFakeEnrollmentKeyStore())

	if _, err := Enroll("ek_1.s", "not-an-nkey", "web-01"); !errors.Is(err, ErrEnrollmentFailed) {
		t.Fatalf("expected ErrEnrollmentFailed, got %v", err)
	}
}

func TestEnroll_InvalidHostname(t *testing.T) {
	setupTestPKI(t)
	store := newFakeEnrollmentKeyStore()
	store.rows["ek_1"] = &enrollmentKeyRow{KeyHash: hashSecret("s"), Expiry: time.Now().Add(time.Hour), MaxUses: 1}
	withFakeEnrollmentKeyStore(t, store)

	if _, err := Enroll("ek_1.s", testEnrollNKey(t), "###bad###"); !errors.Is(err, ErrEnrollmentFailed) {
		t.Fatalf("expected ErrEnrollmentFailed, got %v", err)
	}
	// A bad hostname is a client-side mistake, not a real redemption — it
	// must not burn the token's one use (sprout ID resolution runs before
	// the atomic redeem; see enroll.go's comment on that ordering).
	if store.rows["ek_1"].UsedCount != 0 {
		t.Errorf("expected invalid hostname not to consume a use, used_count=%d", store.rows["ek_1"].UsedCount)
	}
}
