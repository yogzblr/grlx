package pki

// Sprout enrollment: docs/design/grlx-envoy-enrollment-design.md and
// cloudxp-machine-manager-api-design.md §3 ("the one moment in the whole
// system where a caller has no credential yet").
//
// FLAG FOR SECURITY REVIEW per the task brief — this is the literal front
// door of the trust chain: possession of a valid, unexhausted join token
// is the sole authorization check standing between an anonymous caller and
// a signed sprout identity.
//
// Every failure path in Enroll returns the single generic
// ErrEnrollmentFailed sentinel (design doc §3.4) — unknown key_id,
// malformed token, a hash mismatch, revoked, expired, exhausted, and a
// lost redemption race are all deliberately indistinguishable over the
// wire, to deny an attacker an oracle for enumerating key_ids or timing a
// race against expiry. The specific reason is logged locally (log.Warnf
// below) for operator visibility, never returned.
import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/nats-io/nkeys"

	"github.com/gogrlx/grlx/v2/internal/config"
	"github.com/gogrlx/grlx/v2/internal/gatewayjwt"
	log "github.com/gogrlx/grlx/v2/internal/log"
)

// ErrEnrollmentFailed is the single error every enrollment failure mode
// collapses to before crossing the HTTP boundary (design doc §3.4).
var ErrEnrollmentFailed = errors.New("enrollment_failed")

// gatewayJWTMinter abstracts minting the Envoy-facing companion token
// (internal/gatewayjwt — see its package doc for why a second token
// exists at all: the NATS User JWT's "ed25519-nkey" alg header isn't
// something a standard JOSE validator like Envoy's jwt_authn recognizes).
// An interface here, rather than a direct *gatewayjwt.GatewaySigner
// dependency, lets tests swap in a fake instead of requiring a live
// OpenBao Transit backend — the same reasoning as enrollmentKeyStore
// above.
type gatewayJWTMinter interface {
	MintGatewayJWT(ctx context.Context, claims gatewayjwt.GatewayClaims) (string, error)
}

// gatewayMinter is nil until SetGatewaySigner is called (see
// cmd/farmer/main.go). Enroll fails closed — ErrEnrollmentFailed, not a
// panic or a response silently missing gateway_jwt — if it's still nil
// when an enrollment is attempted.
var gatewayMinter gatewayJWTMinter

// SetGatewaySigner installs the signer Enroll mints gateway JWTs
// through. Call once at startup, after gatewayjwt.NewGatewaySigner.
func SetGatewaySigner(s gatewayJWTMinter) { gatewayMinter = s }

// enrollmentKeyRow mirrors the columns of saas.enrollment_keys this farmer
// is granted SELECT on (design doc §4.1/§5.1). It deliberately excludes
// asset_id: that column belongs to the not-yet-built §1.3 asset-linking
// work and isn't part of internal/saasapi/model.go's EnrollmentKey struct
// yet either.
type enrollmentKeyRow struct {
	TenantID  string
	KeyHash   string
	Expiry    time.Time
	MaxUses   int
	UsedCount int
	Revoked   bool
}

// enrollmentKeyStore abstracts reads/writes against saas.enrollment_keys.
// The production implementation (mysqlEnrollmentKeyStore, below) issues
// raw, schema-qualified SQL against this package's shared `db` handle —
// which in production points at the same PXC cluster farmer's own schema
// lives in (design doc §5.1: single cluster, cross-schema grants), but in
// this package's tests is an in-memory SQLite database (see
// pki_test.go's newTestDB) that can't run MySQL-specific cross-schema SQL
// (schema-qualified table names, NOW(), etc.). Tests install a fake here
// instead of standing up a real MySQL instance.
type enrollmentKeyStore interface {
	lookup(keyID string) (*enrollmentKeyRow, error)
	// redeem performs design doc §3.3 step 4's atomic check-and-increment,
	// returning whether this call actually redeemed a use (false means the
	// WHERE guard didn't match — the key was exhausted/revoked/expired by
	// the time this ran, including losing a race to a concurrent redeemer).
	redeem(keyID string) (bool, error)
}

var enrollKeyStore enrollmentKeyStore = mysqlEnrollmentKeyStore{}

type mysqlEnrollmentKeyStore struct{}

func (mysqlEnrollmentKeyStore) lookup(keyID string) (*enrollmentKeyRow, error) {
	var row enrollmentKeyRow
	err := db.Raw(
		`SELECT tenant_id, key_hash, expiry, max_uses, used_count, revoked
		 FROM saas.enrollment_keys WHERE key_id = ?`, keyID,
	).Row().Scan(&row.TenantID, &row.KeyHash, &row.Expiry, &row.MaxUses, &row.UsedCount, &row.Revoked)
	if err != nil {
		return nil, err
	}
	return &row, nil
}

func (mysqlEnrollmentKeyStore) redeem(keyID string) (bool, error) {
	res := db.Exec(
		`UPDATE saas.enrollment_keys
		 SET used_count = used_count + 1, last_used_at = NOW()
		 WHERE key_id = ? AND used_count < max_uses AND revoked = FALSE AND expiry > NOW()`,
		keyID,
	)
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected == 1, nil
}

// EnrollResult is what a successful Enroll call hands back to the HTTP
// layer for the design doc §3.2 success response.
type EnrollResult struct {
	SproutID string
	// JWT is the native NATS User JWT (workstream B, "ed25519-nkey" alg)
	// — what nats-server itself validates. Unchanged by the gateway JWT
	// work below.
	JWT string
	// GatewayJWT is the standard alg:EdDSA companion token
	// (internal/gatewayjwt) presented to Envoy's jwt_authn-gated wss://
	// and recipe-download routes. Minted fresh on every enrollment
	// response, including idempotent replays — it's meant to be
	// short-lived (config.GatewayJWTTTL), unlike the cached-to-disk NATS
	// JWT above.
	GatewayJWT string
	// TenantX25519Pub is the tenant's NaCl box public key — see
	// tenantbox.go's doc comment for why this is an interim, locally-held
	// placeholder rather than workstream J/F's OpenBao-custodied material.
	TenantX25519Pub string
}

// Enroll implements design doc §3.3's step-by-step flow end to end: the
// idempotency check, join-token lookup/validation, atomic redemption, and
// minting. This repo runs farmer and the bus in one process, so there's no
// internal.sprout.mint NATS hop here (cloudxp-machine-manager-api-design.md
// §2.2's subject exists for a split SaaS-API/farmer deployment this repo
// doesn't have yet) — farmer validates the token against saas schema
// directly and mints the JWT itself, in one call.
func Enroll(ctx context.Context, joinToken, nkeyPub, hostname string) (*EnrollResult, error) {
	if !nkeys.IsValidPublicUserKey(nkeyPub) {
		log.Warnf("enroll: rejected malformed nkey_pub")
		return nil, ErrEnrollmentFailed
	}

	// Step 1 (design doc §3.3): idempotency check first, before the join
	// token is even looked at. A sprout retrying after a dropped
	// connection generates its keypair once, locally, before ever calling
	// out — so a retry presents the same nkey_pub and should get the same
	// identity back rather than burning a second use of a possibly
	// single-use token.
	if sproutID, err := SproutIDForNKey(nkeyPub); err == nil {
		return replayExistingEnrollment(ctx, sproutID, nkeyPub)
	}

	keyID, secret, ok := splitJoinToken(joinToken)
	if !ok {
		log.Warnf("enroll: malformed join token")
		return nil, ErrEnrollmentFailed
	}

	row, err := enrollKeyStore.lookup(keyID)
	if errors.Is(err, sql.ErrNoRows) {
		log.Warnf("enroll: unknown key_id %s", keyID)
		return nil, ErrEnrollmentFailed
	}
	if err != nil {
		log.Errorf("enroll: looking up key_id %s: %v", keyID, err)
		return nil, ErrEnrollmentFailed
	}

	if subtle.ConstantTimeCompare([]byte(hashSecret(secret)), []byte(row.KeyHash)) != 1 {
		log.Warnf("enroll: key_id %s presented a secret that did not match", keyID)
		return nil, ErrEnrollmentFailed
	}

	now := time.Now().UTC()
	switch {
	case row.Revoked:
		log.Warnf("enroll: key_id %s is revoked", keyID)
		return nil, ErrEnrollmentFailed
	case now.After(row.Expiry):
		log.Warnf("enroll: key_id %s is expired", keyID)
		return nil, ErrEnrollmentFailed
	case row.UsedCount >= row.MaxUses:
		log.Warnf("enroll: key_id %s is exhausted", keyID)
		return nil, ErrEnrollmentFailed
	}

	// Resolve the sprout ID before redeeming the token below: this is
	// pure local computation over hostname/nkeyPub, so failing here (bad
	// hostname, too many colliding sprouts) shouldn't burn a use of an
	// otherwise-valid, possibly-single-use token — a client-side mistake
	// on the request shouldn't have the same cost as a real redemption.
	sproutID, err := resolveEnrollSproutID(hostname, nkeyPub)
	if err != nil {
		log.Errorf("enroll: resolving sprout id for hostname %q: %v", hostname, err)
		return nil, ErrEnrollmentFailed
	}

	// Note: row.TenantID is validated to exist but is deliberately not
	// threaded into the tenant scoping below — this package's PKI storage
	// (store.go's tenantID()) is still the single-tenant-per-process
	// placeholder every other lifecycle function here uses, pending
	// workstream E's real multi-tenancy. Enrolling against a key issued
	// for a tenant other than this farmer's configured one isn't
	// meaningfully different from today's single-tenant behavior, but is
	// worth knowing about before this ships multi-tenant.
	redeemed, err := enrollKeyStore.redeem(keyID)
	if err != nil {
		log.Errorf("enroll: redeeming key_id %s: %v", keyID, err)
		return nil, ErrEnrollmentFailed
	}
	if !redeemed {
		log.Warnf("enroll: key_id %s lost the atomic redemption race (exhausted/revoked/expired between lookup and redeem)", keyID)
		return nil, ErrEnrollmentFailed
	}

	if err := acceptEnrolledNKey(sproutID, nkeyPub); err != nil {
		log.Errorf("enroll: accepting sprout %s: %v", sproutID, err)
		return nil, ErrEnrollmentFailed
	}

	signedJWT, err := GetSproutUserJWT(sproutID)
	if err != nil {
		log.Errorf("enroll: sprout %s accepted but no readable JWT: %v", sproutID, err)
		return nil, ErrEnrollmentFailed
	}
	tenantPub, err := GetTenantX25519PublicKey()
	if err != nil {
		log.Errorf("enroll: sprout %s enrolled but failed to load tenant X25519 key: %v", sproutID, err)
		return nil, ErrEnrollmentFailed
	}
	gatewayJWT, err := mintGatewayJWTFor(ctx, sproutID, nkeyPub)
	if err != nil {
		log.Errorf("enroll: sprout %s enrolled but failed to mint gateway JWT: %v", sproutID, err)
		return nil, ErrEnrollmentFailed
	}

	log.Infof("enroll: sprout %s enrolled via key_id %s", sproutID, keyID)
	return &EnrollResult{SproutID: sproutID, JWT: signedJWT, GatewayJWT: gatewayJWT, TenantX25519Pub: tenantPub}, nil
}

// replayExistingEnrollment handles design doc §3.3 step 1: an already-
// accepted nkey_pub gets its existing identity back, no token touched.
// The gateway JWT is still minted fresh — see EnrollResult.GatewayJWT's
// doc comment on why it isn't cached like the NATS JWT is.
func replayExistingEnrollment(ctx context.Context, sproutID, nkeyPub string) (*EnrollResult, error) {
	existingJWT, err := GetSproutUserJWT(sproutID)
	if err != nil {
		log.Errorf("enroll: sprout %s has an accepted nkey but no readable JWT: %v", sproutID, err)
		return nil, ErrEnrollmentFailed
	}
	tenantPub, err := GetTenantX25519PublicKey()
	if err != nil {
		log.Errorf("enroll: idempotent replay for %s but failed to load tenant X25519 key: %v", sproutID, err)
		return nil, ErrEnrollmentFailed
	}
	gatewayJWT, err := mintGatewayJWTFor(ctx, sproutID, nkeyPub)
	if err != nil {
		log.Errorf("enroll: idempotent replay for %s but failed to mint gateway JWT: %v", sproutID, err)
		return nil, ErrEnrollmentFailed
	}
	log.Infof("enroll: sprout %s replayed an existing enrollment (idempotency check)", sproutID)
	return &EnrollResult{SproutID: sproutID, JWT: existingJWT, GatewayJWT: gatewayJWT, TenantX25519Pub: tenantPub}, nil
}

// mintGatewayJWTFor builds this sprout's gateway-JWT claims and mints it
// via the installed gatewayMinter (SetGatewaySigner). Both of Enroll's
// success paths call this, per the implementation brief's "Both tokens
// must be minted in the same call — don't split into two round-trips"
// and "don't special-case rotation to mint only one token."
func mintGatewayJWTFor(ctx context.Context, sproutID, nkeyPub string) (string, error) {
	if gatewayMinter == nil {
		return "", errors.New("pki: no gateway JWT signer configured (SetGatewaySigner was never called)")
	}
	return gatewayMinter.MintGatewayJWT(ctx, gatewayjwt.GatewayClaims{
		Subject:  nkeyPub,
		TenantID: tenantID(),
		SproutID: sproutID,
		Expiry:   time.Now().Add(config.GatewayJWTTTL),
	})
}

// splitJoinToken splits design doc §3.1's "{key_id}.{secret}" token on its
// first '.', rejecting anything that doesn't leave both halves non-empty.
func splitJoinToken(token string) (keyID, secret string, ok bool) {
	i := strings.IndexByte(token, '.')
	if i <= 0 || i == len(token)-1 {
		return "", "", false
	}
	return token[:i], token[i+1:], true
}

// hashSecret must stay byte-for-byte identical to internal/saasapi's own
// hashSecret (idgen.go): both sides hash the secret half of the same
// {key_id}.{secret} token the same way. farmer can't import
// internal/saasapi (separate schema/service boundary — design doc §5.1's
// "SaaS API" vs. "Farmer" split), so this is a deliberate, small
// duplication rather than a cross-service dependency.
func hashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// resolveEnrollSproutID picks the sprout ID an enrolling host gets,
// applying the same hostname normalization and same-nkey/collision
// handling as the legacy PutNKey path
// (internal/api/handlers/pki.go) so both mechanisms agree on how a
// hostname becomes a sprout ID.
func resolveEnrollSproutID(hostname, nkeyPub string) (string, error) {
	base := strings.ToLower(hostname)
	base = strings.ReplaceAll(base, "_", "-")
	base = strings.TrimPrefix(base, "-")
	if !IsValidSproutID(base) {
		return "", ErrSproutIDInvalid
	}
	if registered, matches := NKeyExists(base, nkeyPub); !registered || matches {
		return base, nil
	}
	for i := 1; i < 100; i++ {
		id := base + "_" + strconv.Itoa(i)
		if registered, matches := NKeyExists(id, nkeyPub); !registered || matches {
			return id, nil
		}
	}
	return "", errors.New("pki: too many sprouts sharing hostname " + base)
}

// acceptEnrolledNKey upserts sprout directly into the accepted state in
// one write. Unlike the legacy Unaccept-then-admin-Accept flow, presenting
// a valid, unexhausted join token *is* the authorization decision here —
// there's no separate pending-review step to go through first.
func acceptEnrolledNKey(id, nkey string) error {
	defer func() {
		if err := ReloadNKeys(); err != nil {
			log.Errorf("failed to reload NATS auth for enrolled sprout %s: %v", id, err)
		}
	}()
	return upsertNKeyRow(nkeyRow{TenantID: tenantID(), SproutID: id, NKey: nkey, State: stateAccepted})
}
