package pki

// Maps grlx's accept/deny/reject/unaccept sprout lifecycle onto NATS JWT
// issuance and revocation, per docs/design/grlx-nats-jwt-auth-design.md's
// "Revocation semantics" open item.
//
// Two independent pieces of state are kept in sync here, and it's worth
// keeping them distinct:
//   - The tenant Account's revocation list (inside its signed JWT) is what
//     the bus actually enforces. A pubkey with a revocation entry can never
//     authenticate with a User JWT issued at or before that timestamp,
//     regardless of whether such a JWT exists. Changing this list is the
//     only thing that requires re-signing the Account JWT and pushing it to
//     the resolver (see resolver.go) — that's the expensive, network-facing
//     operation.
//   - Each sprout/farmer/cli-admin's own signed User JWT is minted once and
//     cached to a local file so it can be handed back out (e.g. by the
//     enrollment endpoint workstream H builds) without re-signing. Minting
//     or reusing this file never itself requires a push: the resolver never
//     stores User JWTs, only Account JWTs.
import (
	"os"
	"path/filepath"

	jwt "github.com/nats-io/jwt/v2"

	"github.com/gogrlx/grlx/v2/internal/auth"
	log "github.com/gogrlx/grlx/v2/internal/log"
)

func allowAllPermissions() jwt.Permissions {
	return jwt.Permissions{
		Pub: jwt.Permission{Allow: jwt.StringList{"grlx.>", "_INBOX.>"}},
		Sub: jwt.Permission{Allow: jwt.StringList{"grlx.>", "_INBOX.>"}},
	}
}

func sproutPermissions(id string) jwt.Permissions {
	return jwt.Permissions{
		Pub: jwt.Permission{Allow: jwt.StringList{
			"grlx.sprouts.announce." + id,
			"_INBOX.>",
			"grlx.cook." + id + ".>",
			"grlx.sprouts." + id + ".facts",
		}},
		Sub: jwt.Permission{Allow: jwt.StringList{
			"grlx.sprouts." + id + ".>",
		}},
	}
}

// ensureUserGranted clears any revocation entry for pubkey in ac. It
// reports whether it actually changed ac (i.e. a push is now needed).
func ensureUserGranted(ac *jwt.AccountClaims, pubkey string) bool {
	if _, revoked := ac.Revocations[pubkey]; revoked {
		ac.ClearRevocation(pubkey)
		return true
	}
	return false
}

// ensureUserRevoked adds a revocation entry (effective now) for pubkey in
// ac, if one isn't already present. It reports whether it actually changed
// ac (i.e. a push is now needed).
func ensureUserRevoked(ac *jwt.AccountClaims, pubkey string) bool {
	if _, revoked := ac.Revocations[pubkey]; revoked {
		return false
	}
	ac.Revoke(pubkey)
	return true
}

// mintOrReuseUserJWT (re)mints a signed User JWT for pubkey under the
// tenant account and persists it to path, unless a JWT already on disk at
// path is still current (same subject pubkey). Returns whether a new JWT
// was written.
func mintOrReuseUserJWT(path, pubkey, name string, perms jwt.Permissions, mat *natsAuthMaterial) (bool, error) {
	if b, err := os.ReadFile(path); err == nil {
		if existing, derr := jwt.DecodeUserClaims(string(b)); derr == nil && existing.Subject == pubkey {
			return false, nil
		}
	} else if !os.IsNotExist(err) {
		return false, err
	}
	uc := jwt.NewUserClaims(pubkey)
	uc.Name = name
	uc.IssuerAccount = mat.tenantPub
	uc.Permissions = perms
	signed, err := uc.Encode(mat.tenantSigningKP)
	if err != nil {
		return false, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return false, err
	}
	if err := os.WriteFile(path, []byte(signed), 0o600); err != nil {
		return false, err
	}
	return true, nil
}

// syncNatsAuth recomputes the tenant Account's User JWTs and revocation
// list from the current accept/deny/reject/unaccept directory state (the
// same "rebuild from directory state" shape the old NKey-allow-list
// ReloadNKeys used), re-signing and persisting the Account JWT if its
// revocation list changed. It reports whether the Account JWT changed
// (i.e. whether ReloadNKeys needs to push an update to the bus).
func syncNatsAuth(mat *natsAuthMaterial) (bool, error) {
	ac, err := loadTenantClaims(mat)
	if err != nil {
		return false, err
	}

	changed := false

	farmerKey, err := GetPubNKey(FarmerPubNKey)
	if err != nil {
		log.Fatalf("Could not load the Farmer's NKey, aborting")
	}
	log.Tracef("Loaded farmer's public key: %s", farmerKey)
	if ensureUserGranted(ac, farmerKey) {
		changed = true
	}
	if _, mintErr := mintOrReuseUserJWT(farmerUserJWTPath(), farmerKey, "farmer", allowAllPermissions(), mat); mintErr != nil {
		log.Errorf("failed to mint farmer User JWT: %v", mintErr)
	}

	grlxKeys, err := auth.GetPubkeysByRole("admin")
	if err != nil {
		log.Errorf("Could not load the grlx cli's NKey(s), please edit the config")
	} else {
		log.Tracef("Loaded grlx cli's public key(s): %v", grlxKeys)
	}
	for _, key := range grlxKeys {
		if ensureUserGranted(ac, key) {
			changed = true
		}
		if _, mintErr := mintOrReuseUserJWT(cliUserJWTPath(key), key, "grlx-cli", allowAllPermissions(), mat); mintErr != nil {
			log.Errorf("failed to mint grlx cli User JWT for %s: %v", key, mintErr)
		}
	}

	for _, s := range GetNKeysByType("accepted").Sprouts {
		log.Tracef("Syncing accepted sprout `%s` onto the tenant Account JWT", s.SproutID)
		key, errGet := GetNKey(s.SproutID)
		if errGet != nil {
			log.Errorf("failed to get NKey for sprout %s: %v", s.SproutID, errGet)
			continue
		}
		if ensureUserGranted(ac, key) {
			changed = true
		}
		if _, mintErr := mintOrReuseUserJWT(sproutJWTPath(s.SproutID), key, s.SproutID, sproutPermissions(s.SproutID), mat); mintErr != nil {
			log.Errorf("failed to mint User JWT for sprout %s: %v", s.SproutID, mintErr)
		}
	}

	for _, state := range []string{"unaccepted", "denied", "rejected"} {
		for _, s := range GetNKeysByType(state).Sprouts {
			key, errGet := GetNKey(s.SproutID)
			if errGet != nil {
				log.Errorf("failed to get NKey for sprout %s: %v", s.SproutID, errGet)
				continue
			}
			if ensureUserRevoked(ac, key) {
				changed = true
			}
		}
	}

	log.Tracef("Completed syncing authorized clients onto the tenant Account JWT.")

	if changed {
		signed, encErr := ac.Encode(mat.operatorSigningKP)
		if encErr != nil {
			return false, encErr
		}
		if writeErr := os.WriteFile(tenantJWTPath(), []byte(signed), 0o600); writeErr != nil {
			return false, writeErr
		}
		mat.tenantJWT = signed
	}
	return changed, nil
}

// FarmerUserJWT returns the farmer's own signed User JWT, minted by
// syncNatsAuth (via ReloadNKeys) into farmerUserJWTPath. cmd/farmer/main.go's
// ConnectFarmer reads this to authenticate the core process's own bus
// connection alongside its NKey seed (config.NKeyFarmerPrivFile) — the same
// User-JWT-plus-seed shape ConnectSystemAccount uses for the SYS push
// connection, replacing the bare-NKey connect that predates this file's JWT
// auth model and can't satisfy a server configured with TrustedOperators.
// ReloadNKeys must have run at least once (main() calls it during farmer
// startup, before ConnectFarmer) so this file exists by the time it's read.
func FarmerUserJWT() (string, error) {
	b, err := os.ReadFile(farmerUserJWTPath())
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// GetSproutUserJWT returns the signed User JWT minted for an accepted
// sprout, if any. This is groundwork for the enrollment endpoint
// (docs/design/grlx-envoy-enrollment-design.md, workstream H) that will
// hand it back to the sprout; nothing in this repo serves it over the wire
// yet.
func GetSproutUserJWT(id string) (string, error) {
	if !IsValidSproutID(id) {
		return "", ErrSproutIDInvalid
	}
	b, err := os.ReadFile(sproutJWTPath(id))
	if err != nil {
		if os.IsNotExist(err) {
			return "", ErrSproutIDNotFound
		}
		return "", err
	}
	return string(b), nil
}
