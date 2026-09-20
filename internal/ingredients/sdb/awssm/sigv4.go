package awssm

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sort"
	"strings"
	"time"
)

// awsCreds are the temporary credentials handed out by IMDSv2 for the
// instance's attached role.
type awsCreds struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
}

// signSigV4 signs req in place per AWS Signature Version 4
// (https://docs.aws.amazon.com/general/latest/gr/sigv4-signing-process.html),
// setting the Host, X-Amz-Date, X-Amz-Security-Token and Authorization
// headers. body is the exact bytes that will be sent as the request body.
func signSigV4(req *http.Request, body []byte, creds awsCreds, region, service string, now time.Time) {
	amzDate := now.UTC().Format("20060102T150405Z")
	dateStamp := now.UTC().Format("20060102")

	req.Host = req.URL.Host
	req.Header.Set("X-Amz-Date", amzDate)
	if creds.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", creds.SessionToken)
	}

	canonicalHeaders, signedHeaders := canonicalizeHeaders(req.Header, req.URL.Host)
	payloadHash := sha256Hex(body)

	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI(req.URL.Path),
		req.URL.RawQuery,
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")

	credentialScope := strings.Join([]string{dateStamp, region, service, "aws4_request"}, "/")
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		credentialScope,
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")

	signingKey := hmacSHA256(hmacSHA256(hmacSHA256(hmacSHA256([]byte("AWS4"+creds.SecretAccessKey), dateStamp), region), service), "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(signingKey, stringToSign))

	authHeader := "AWS4-HMAC-SHA256 " +
		"Credential=" + creds.AccessKeyID + "/" + credentialScope + ", " +
		"SignedHeaders=" + signedHeaders + ", " +
		"Signature=" + signature
	req.Header.Set("Authorization", authHeader)
}

func canonicalURI(path string) string {
	if path == "" {
		return "/"
	}
	return path
}

func canonicalizeHeaders(h http.Header, host string) (canonical, signed string) {
	headers := map[string]string{"host": host}
	for k, v := range h {
		headers[strings.ToLower(k)] = strings.Join(v, ",")
	}
	names := make([]string, 0, len(headers))
	for k := range headers {
		names = append(names, k)
	}
	sort.Strings(names)

	var cb strings.Builder
	for _, name := range names {
		cb.WriteString(name)
		cb.WriteString(":")
		cb.WriteString(strings.TrimSpace(headers[name]))
		cb.WriteString("\n")
	}
	return cb.String(), strings.Join(names, ";")
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func hmacSHA256(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return mac.Sum(nil)
}
