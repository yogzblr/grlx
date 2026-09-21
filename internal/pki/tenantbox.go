package pki

// Interim, locally-generated placeholder for the tenant's X25519 keypair
// that docs/design/grlx-payload-encryption-design.md (workstream J)
// bootstraps in the same enrollment round trip as this file's sibling,
// enroll.go.
//
// FLAG FOR SECURITY REVIEW: this is *not* workstream J, and it is
// deliberately narrow. It generates and stores the tenant's X25519
// private key locally, analogous to jwtauth.go's operator/account NKey
// material and with the same interim caveat that file's header states:
// the intended production custody is OpenBao (workstream F), not a flat
// file on the farmer's own disk. This file exists only so the enrollment
// response (cloudxp-machine-manager-api-design.md §3.2) can return a real
// public key today. Actually wrapping NATS payloads in NaCl box using
// this keypair, per-sprout key generation/exchange, and key rotation are
// all workstream J's remaining, unbuilt scope — nothing in this repo
// reads the private key this file writes except this file itself.
import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/nacl/box"
)

var (
	tenantBoxMu   sync.Mutex
	tenantBoxPub  *[32]byte
	tenantBoxPriv *[32]byte
)

func tenantX25519PrivPath() string {
	return filepath.Join(natsAuthDir(), "tenant-x25519.key")
}

func tenantX25519PubPath() string {
	return filepath.Join(natsAuthDir(), "tenant-x25519.pub")
}

// resetTenantX25519KeypairCache clears the in-process cache so the next
// call reloads from disk. Test-only.
func resetTenantX25519KeypairCache() {
	tenantBoxMu.Lock()
	defer tenantBoxMu.Unlock()
	tenantBoxPub, tenantBoxPriv = nil, nil
}

// ensureTenantX25519Keypair loads the tenant's NaCl box keypair from disk,
// generating and persisting it (private half, 0600) on first use. Safe to
// call repeatedly and concurrently.
func ensureTenantX25519Keypair() (pub, priv *[32]byte, err error) {
	tenantBoxMu.Lock()
	defer tenantBoxMu.Unlock()

	if tenantBoxPub != nil {
		return tenantBoxPub, tenantBoxPriv, nil
	}

	privPath := tenantX25519PrivPath()
	pubPath := tenantX25519PubPath()

	privBytes, privErr := os.ReadFile(privPath)
	pubBytes, pubErr := os.ReadFile(pubPath)
	if privErr == nil && pubErr == nil {
		if len(privBytes) != 32 || len(pubBytes) != 32 {
			return nil, nil, fmt.Errorf("pki: tenant X25519 key files at %s/%s are not 32 bytes", privPath, pubPath)
		}
		var sk, pk [32]byte
		copy(sk[:], privBytes)
		copy(pk[:], pubBytes)
		tenantBoxPriv, tenantBoxPub = &sk, &pk
		return tenantBoxPub, tenantBoxPriv, nil
	}
	if privErr != nil && !os.IsNotExist(privErr) {
		return nil, nil, privErr
	}
	if pubErr != nil && !os.IsNotExist(pubErr) {
		return nil, nil, pubErr
	}

	pk, sk, genErr := box.GenerateKey(rand.Reader)
	if genErr != nil {
		return nil, nil, genErr
	}
	if err := os.MkdirAll(filepath.Dir(privPath), 0o700); err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(privPath, sk[:], 0o600); err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(pubPath, pk[:], 0o644); err != nil {
		return nil, nil, err
	}
	tenantBoxPub, tenantBoxPriv = pk, sk
	return pk, sk, nil
}

// GetTenantX25519PublicKey returns the tenant's NaCl box public key,
// standard-base64-encoded, for inclusion in the enrollment response
// (cloudxp-machine-manager-api-design.md §3.2).
func GetTenantX25519PublicKey() (string, error) {
	pub, _, err := ensureTenantX25519Keypair()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(pub[:]), nil
}
