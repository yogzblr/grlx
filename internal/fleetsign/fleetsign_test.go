package fleetsign

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testChecksum = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

func testRelease() Release {
	return Release{
		Version:        "v2.4.1",
		ArtifactURL:    "https://artifacts.example.com/sprout-v2.4.1-linux-amd64",
		ChecksumSHA256: testChecksum,
	}
}

// signForTest plays cmd/fleetreleaser's role with a local key, so the
// verify path is tested against a real Ed25519 signature over the real
// canonical message.
func signForTest(t *testing.T, priv ed25519.PrivateKey, keyVersion int, r Release) string {
	t.Helper()
	msg, err := r.Message()
	if err != nil {
		t.Fatalf("Message: %v", err)
	}
	return EncodeSignature(keyVersion, ed25519.Sign(priv, msg))
}

func newTestKey(t *testing.T, version int) (PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return PublicKey{Version: version, Key: pub}, priv
}

func TestMessage_Canonical(t *testing.T) {
	msg, err := testRelease().Message()
	if err != nil {
		t.Fatalf("Message: %v", err)
	}
	want := "v2.4.1|https://artifacts.example.com/sprout-v2.4.1-linux-amd64|" + testChecksum
	if string(msg) != want {
		t.Fatalf("Message = %q, want %q", msg, want)
	}
}

func TestMessage_RejectsAmbiguousOrInvalidFields(t *testing.T) {
	cases := map[string]func(*Release){
		"empty version":        func(r *Release) { r.Version = "" },
		"pipe in version":      func(r *Release) { r.Version = "v1|x" },
		"pipe in url":          func(r *Release) { r.ArtifactURL = "https://a.example.com/x|y" },
		"control char":         func(r *Release) { r.Version = "v1\n" },
		"http url":             func(r *Release) { r.ArtifactURL = "http://a.example.com/x" },
		"url with userinfo":    func(r *Release) { r.ArtifactURL = "https://u:p@a.example.com/x" },
		"relative url":         func(r *Release) { r.ArtifactURL = "/x" },
		"uppercase checksum":   func(r *Release) { r.ChecksumSHA256 = strings.ToUpper(testChecksum) },
		"short checksum":       func(r *Release) { r.ChecksumSHA256 = testChecksum[:62] },
		"non-hex checksum":     func(r *Release) { r.ChecksumSHA256 = strings.Repeat("z", 64) },
		"version too long":     func(r *Release) { r.Version = strings.Repeat("v", maxVersionLen+1) },
		"artifact url too big": func(r *Release) { r.ArtifactURL = "https://a.example.com/" + strings.Repeat("x", maxArtifactURLLen) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := testRelease()
			mutate(&r)
			if _, err := r.Message(); !errors.Is(err, ErrInvalidRelease) {
				t.Fatalf("Message error = %v, want ErrInvalidRelease", err)
			}
		})
	}
}

func TestSignatureEncoding_RoundTrip(t *testing.T) {
	sig := make([]byte, ed25519.SignatureSize)
	sig[0] = 7
	enc := EncodeSignature(3, sig)
	if !strings.HasPrefix(enc, "v3:") {
		t.Fatalf("EncodeSignature = %q, want v3: prefix", enc)
	}
	v, got, err := DecodeSignature(enc)
	if err != nil || v != 3 || string(got) != string(sig) {
		t.Fatalf("DecodeSignature = %d, %x, %v", v, got, err)
	}
}

func TestDecodeSignature_Malformed(t *testing.T) {
	good := EncodeSignature(1, make([]byte, ed25519.SignatureSize))
	for _, s := range []string{
		"garbage", "1:" + good[3:], "v:" + good[3:], "v0:" + good[3:], "v01:" + good[3:], "v-1:" + good[3:],
		"v1:not base64!", "v1:" + good[3:len(good)-8], "vault:v1:" + good[3:],
	} {
		if _, _, err := DecodeSignature(s); !errors.Is(err, ErrMalformedSignature) {
			t.Errorf("DecodeSignature(%q) = %v, want ErrMalformedSignature", s, err)
		}
	}
}

func TestVerify_Valid(t *testing.T) {
	pub, priv := newTestKey(t, 1)
	ks, err := NewKeySet([]PublicKey{pub})
	if err != nil {
		t.Fatalf("NewKeySet: %v", err)
	}
	if err := ks.Verify(testRelease(), signForTest(t, priv, 1, testRelease())); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// A tampered row — the artifact URL (or version) swapped after signing,
// checksum still a perfectly valid hash of *some* binary — must be
// refused: the signature binds all three fields, not just the hash.
func TestVerify_TamperedRowValidHashInvalidSignature(t *testing.T) {
	pub, priv := newTestKey(t, 1)
	ks, _ := NewKeySet([]PublicKey{pub})
	sig := signForTest(t, priv, 1, testRelease())

	tampered := []func(*Release){
		func(r *Release) { r.ArtifactURL = "https://evil.example.com/sprout" },
		func(r *Release) { r.Version = "v9.9.9" },
		func(r *Release) {
			r.ChecksumSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" // sha256("")
		},
	}
	for i, mutate := range tampered {
		r := testRelease()
		mutate(&r)
		if err := ks.Verify(r, sig); !errors.Is(err, ErrInvalidSignature) {
			t.Errorf("case %d: Verify = %v, want ErrInvalidSignature", i, err)
		}
	}
}

func TestVerify_SignatureFromOtherKeyRefused(t *testing.T) {
	pub, _ := newTestKey(t, 1)
	_, otherPriv := newTestKey(t, 1)
	ks, _ := NewKeySet([]PublicKey{pub})
	if err := ks.Verify(testRelease(), signForTest(t, otherPriv, 1, testRelease())); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("Verify = %v, want ErrInvalidSignature", err)
	}
}

// An un-migrated fleet_versions row has signature = "": that is a
// refusal, never a fallback to checksum-only trust.
func TestVerify_MissingSignatureRefused(t *testing.T) {
	pub, _ := newTestKey(t, 1)
	ks, _ := NewKeySet([]PublicKey{pub})
	if err := ks.Verify(testRelease(), ""); !errors.Is(err, ErrMissingSignature) {
		t.Fatalf("Verify = %v, want ErrMissingSignature", err)
	}
}

func TestVerify_UnknownKeyVersionRefused(t *testing.T) {
	pub, priv := newTestKey(t, 1)
	ks, _ := NewKeySet([]PublicKey{pub})
	if err := ks.Verify(testRelease(), signForTest(t, priv, 2, testRelease())); !errors.Is(err, ErrUnknownKeyVersion) {
		t.Fatalf("Verify = %v, want ErrUnknownKeyVersion", err)
	}
}

func TestVerify_EmptyKeySetRefused(t *testing.T) {
	_, priv := newTestKey(t, 1)
	if err := KeySet(nil).Verify(testRelease(), signForTest(t, priv, 1, testRelease())); !errors.Is(err, ErrNoKeys) {
		t.Fatalf("Verify = %v, want ErrNoKeys", err)
	}
	// A KeySet built by hand with a truncated key must fail, not panic.
	bad := KeySet{{Version: 1, Key: ed25519.PublicKey{1, 2, 3}}}
	if err := bad.Verify(testRelease(), signForTest(t, priv, 1, testRelease())); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("Verify with truncated key = %v, want ErrInvalidSignature", err)
	}
}

func TestNewKeySet_Validation(t *testing.T) {
	k1, _ := newTestKey(t, 1)
	if _, err := NewKeySet(nil); !errors.Is(err, ErrNoKeys) {
		t.Errorf("empty: %v", err)
	}
	if _, err := NewKeySet([]PublicKey{k1, k1}); err == nil {
		t.Error("duplicate version accepted")
	}
	if _, err := NewKeySet([]PublicKey{{Version: 0, Key: k1.Key}}); err == nil {
		t.Error("version 0 accepted")
	}
	if _, err := NewKeySet([]PublicKey{{Version: 1, Key: k1.Key[:10]}}); err == nil {
		t.Error("short key accepted")
	}
	k2, _ := newTestKey(t, 2)
	ks, err := NewKeySet([]PublicKey{k2, k1})
	if err != nil || ks[0].Version != 1 || ks[1].Version != 2 {
		t.Errorf("NewKeySet not sorted: %+v, %v", ks, err)
	}
}

// TestNoSigningCodeInPackage keeps this package's shape honest: it is
// imported by farmer, saasapi and sprout, none of which may sign. The
// real enforcement is OpenBao policy (cmd/fleetreleaser's
// TestOpenBaoEnforcesReadOnlyFleetKey); this only catches someone copying
// gatewayjwt's sign method in here by accident.
func TestNoSigningCodeInPackage(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"/sign/", "ed25519.Sign(", "ed25519.PrivateKey", "/rotate"} {
			if strings.Contains(string(src), forbidden) {
				t.Errorf("%s contains %q: fleetsign must stay verify-only", f, forbidden)
			}
		}
	}
}
