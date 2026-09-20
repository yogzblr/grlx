package awssm

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestSignSigV4_KnownVector checks our from-scratch SigV4 implementation
// against a fixed request signed independently (Python's hashlib/hmac,
// following the same documented algorithm) rather than trusting a single
// implementation of a security-sensitive routine to grade itself.
func TestSignSigV4_KnownVector(t *testing.T) {
	body := []byte(`{"SecretId":"prod/db"}`)
	req, err := http.NewRequest(http.MethodPost, "https://secretsmanager.us-east-1.amazonaws.com/", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "secretsmanager.GetSecretValue")

	creds := awsCreds{
		AccessKeyID:     "AKIDEXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		SessionToken:    "TESTSESSIONTOKEN",
	}
	fixedTime := time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)

	signSigV4(req, body, creds, "us-east-1", "secretsmanager", fixedTime)

	const wantAuth = "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/secretsmanager/aws4_request, " +
		"SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-amz-target, " +
		"Signature=243bfdb30dd388415af7edde48fa2080da1cc3418030a2bc2aa554ce37e881f8"

	if got := req.Header.Get("Authorization"); got != wantAuth {
		t.Errorf("Authorization header mismatch:\n got: %s\nwant: %s", got, wantAuth)
	}
	if got := req.Header.Get("X-Amz-Date"); got != "20150830T123600Z" {
		t.Errorf("X-Amz-Date = %q, want %q", got, "20150830T123600Z")
	}
	if got := req.Header.Get("X-Amz-Security-Token"); got != "TESTSESSIONTOKEN" {
		t.Errorf("X-Amz-Security-Token = %q, want %q", got, "TESTSESSIONTOKEN")
	}
	if req.Host != "secretsmanager.us-east-1.amazonaws.com" {
		t.Errorf("req.Host = %q, want %q", req.Host, "secretsmanager.us-east-1.amazonaws.com")
	}
}

func TestSignSigV4_NoSessionToken(t *testing.T) {
	body := []byte(`{}`)
	req, err := http.NewRequest(http.MethodPost, "https://secretsmanager.us-east-1.amazonaws.com/", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	creds := awsCreds{AccessKeyID: "AKID", SecretAccessKey: "secret"}
	signSigV4(req, body, creds, "us-east-1", "secretsmanager", time.Now())

	if got := req.Header.Get("X-Amz-Security-Token"); got != "" {
		t.Errorf("expected no X-Amz-Security-Token without a session token, got %q", got)
	}
	auth := req.Header.Get("Authorization")
	if !strings.Contains(auth, "Credential=AKID/") {
		t.Errorf("Authorization header missing expected credential: %q", auth)
	}
	if strings.Contains(auth, "x-amz-security-token") {
		t.Errorf("SignedHeaders should not list x-amz-security-token when there's no session token: %q", auth)
	}
}
