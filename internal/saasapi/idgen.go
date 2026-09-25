// Security-sensitive: this file generates and hashes enrollment-key
// secrets (design doc §3.1). FLAG FOR SECURITY REVIEW per the task brief —
// review the randomness source, encoding, and the fact that the raw
// secret is never persisted, only its SHA-256 hash.
//
// Logging safety: this file deliberately has no logging of any kind — it
// does not import internal/log (or any other logger), never writes to
// stdout/stderr, and its only fmt use is fmt.Errorf wrapping the
// underlying crypto/rand error, never the secret, its bytes, or its hash.
// Verified by read-through for the enrollment-key logging-safety review
// and pinned by TestIdgenHasNoLoggingOrSecretBearingErrors in
// idgen_test.go, which parses this file and fails if that ever changes.
// Don't add a "debug" log line here: every value this file produces is
// either a secret or derived from one, and errors should be logged (if at
// all) by the caller, which only ever sees the wrapped rand error.
package saasapi

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// idEncoding renders random IDs (tenant_id, key_id) in lowercase base32
// (Crockford's alphabet minus ambiguous chars isn't needed here since these
// aren't hand-typed) without padding, matching the short, opaque style of
// the design doc's examples ("t_8f2a", "ek_91cd").
var idEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// idRandomBytes is the number of random bytes backing a generated ID's
// suffix. The design doc's examples are illustrative 4-char shorthand;
// 10 random bytes (16 base32 chars) gives collision resistance suitable
// for a system provisioning many tenants/keys, not just doc-example scale.
const idRandomBytes = 10

// enrollmentSecretBytes is the size of the random secret half of an
// enrollment token, per design doc §3.1 ("a 32-byte random value").
const enrollmentSecretBytes = 32

// newID generates a random, prefixed, lowercase identifier such as
// "t_" + 16 base32 chars, or "ek_" + 16 base32 chars.
func newID(prefix string) (string, error) {
	b := make([]byte, idRandomBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("saasapi: generating id: %w", err)
	}
	return prefix + toLower(idEncoding.EncodeToString(b)), nil
}

// newEnrollmentSecret generates the secret half of an enrollment token
// (design doc §3.1). The returned string is URL-safe and is never stored;
// only hashSecret's output is persisted (EnrollmentKey.KeyHash).
func newEnrollmentSecret() (string, error) {
	b := make([]byte, enrollmentSecretBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("saasapi: generating enrollment secret: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// hashSecret returns the hex-encoded SHA-256 hash of secret, which is what
// gets stored in EnrollmentKey.KeyHash. The raw secret itself is returned
// to the caller exactly once (in the POST response) and is never written
// to the database or logs.
func hashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

func toLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c - 'A' + 'a'
		}
	}
	return string(b)
}
