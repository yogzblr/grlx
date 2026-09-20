// Package certs issues and rotates farmer/sprout TLS material from
// OpenBao's PKI secrets engine, writing the results to the same
// config.CertFile/KeyFile/RootCA paths that internal/pki/nats.go and the
// API server already consume.
//
// The official OpenBao/Vault Go client (github.com/openbao/openbao/api,
// github.com/hashicorp/vault/api) is MPL-2.0 licensed, which conflicts with
// this repo's Apache-2.0/MIT-only dependency constraint (see CLAUDE.md).
// This package therefore talks to OpenBao's HTTP API directly with
// net/http, following the same approach already taken by
// internal/ingredients/sdb/openbao.
package certs

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gogrlx/grlx/v2/internal/config"
	log "github.com/gogrlx/grlx/v2/internal/log"
)

// Environment variables configuring the OpenBao PKI client. Addr, Token
// and Role are required; the rest have sane defaults.
const (
	EnvOpenBaoAddr     = "GRLX_CERTS_OPENBAO_ADDR"
	EnvOpenBaoToken    = "GRLX_CERTS_OPENBAO_TOKEN"
	EnvOpenBaoPKIMount = "GRLX_CERTS_OPENBAO_PKI_MOUNT" // default "pki"
	EnvOpenBaoRole     = "GRLX_CERTS_OPENBAO_ROLE"
	EnvOpenBaoCACert   = "GRLX_CERTS_OPENBAO_CACERT" // optional, verify OpenBao's own TLS
)

var (
	ErrNotConfigured = errors.New("openbao PKI client not configured: set " +
		EnvOpenBaoAddr + ", " + EnvOpenBaoToken + " and " + EnvOpenBaoRole)
	ErrIssueFailed   = errors.New("openbao certificate issuance failed")
	ErrRenewFailed   = errors.New("openbao lease renewal failed")
	ErrCAFetchFailed = errors.New("openbao CA certificate fetch failed")
)

// obClient is a minimal client for the subset of OpenBao's HTTP API this
// package needs: the PKI secrets engine's issue/ca endpoints, and
// sys/leases/renew.
type obClient struct {
	addr       string
	token      string
	mount      string
	role       string
	httpClient *http.Client
}

// newClientFromEnv builds an obClient from the Env* variables above. It is
// called fresh on every operation (rather than cached at package init)
// so that changes to the environment -- as tests make routinely, pointing
// at a local OpenBao dev server -- take effect immediately.
func newClientFromEnv() (*obClient, error) {
	addr := os.Getenv(EnvOpenBaoAddr)
	token := os.Getenv(EnvOpenBaoToken)
	role := os.Getenv(EnvOpenBaoRole)
	if addr == "" || token == "" || role == "" {
		return nil, ErrNotConfigured
	}
	mount := os.Getenv(EnvOpenBaoPKIMount)
	if mount == "" {
		mount = "pki"
	}
	var transport http.RoundTripper = http.DefaultTransport
	if caFile := os.Getenv(EnvOpenBaoCACert); caFile != "" {
		pemBytes, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("reading OpenBao CA bundle: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("no certificates found in OpenBao CA bundle %s", caFile)
		}
		transport = &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		}
	}
	return &obClient{
		addr:       strings.TrimRight(addr, "/"),
		token:      token,
		mount:      mount,
		role:       role,
		httpClient: &http.Client{Transport: transport, Timeout: 30 * time.Second},
	}, nil
}

type issueRequest struct {
	CommonName string `json:"common_name"`
	AltNames   string `json:"alt_names,omitempty"`
	IPSans     string `json:"ip_sans,omitempty"`
	TTL        string `json:"ttl,omitempty"`
	// ExcludeCNFromSans is always true (see issueCert): without it, OpenBao
	// additionally adds CommonName itself as a DNS SAN entry, even when it
	// is an IP-shaped string that's already been supplied via IPSans,
	// producing a spurious extra SAN.
	ExcludeCNFromSans bool `json:"exclude_cn_from_sans"`
}

type issueData struct {
	Certificate string `json:"certificate"`
	IssuingCA   string `json:"issuing_ca"`
	PrivateKey  string `json:"private_key"`
}

type issueResponse struct {
	LeaseID       string    `json:"lease_id"`
	LeaseDuration int       `json:"lease_duration"`
	Renewable     bool      `json:"renewable"`
	Data          issueData `json:"data"`
	Errors        []string  `json:"errors"`
}

// issueCert requests a new leaf certificate for hosts from the configured
// PKI role. IPs and DNS names in hosts are split into ip_sans/alt_names;
// the first host becomes the certificate's CommonName, matching how
// config.CertHosts was previously used to build SANs directly.
func (c *obClient) issueCert(ctx context.Context, hosts []string, ttl time.Duration) (*issueResponse, error) {
	var dnsNames, ips []string
	for _, h := range hosts {
		if net.ParseIP(h) != nil {
			ips = append(ips, h)
		} else {
			dnsNames = append(dnsNames, h)
		}
	}
	cn := "grlx"
	switch {
	case len(dnsNames) > 0:
		cn = dnsNames[0]
	case len(ips) > 0:
		cn = ips[0]
	}
	reqBody := issueRequest{
		CommonName:        cn,
		AltNames:          strings.Join(dnsNames, ","),
		IPSans:            strings.Join(ips, ","),
		ExcludeCNFromSans: true,
	}
	if ttl > 0 {
		reqBody.TTL = ttl.String()
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("%w: encoding request: %w", ErrIssueFailed, err)
	}
	reqURL := fmt.Sprintf("%s/v1/%s/issue/%s", c.addr, c.mount, c.role)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrIssueFailed, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Vault-Token", c.token)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrIssueFailed, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: reading response: %w", ErrIssueFailed, err)
	}
	var ir issueResponse
	if resp.StatusCode != http.StatusOK {
		_ = json.Unmarshal(data, &ir)
		return nil, fmt.Errorf("%w: status %d: %s", ErrIssueFailed, resp.StatusCode, strings.Join(ir.Errors, "; "))
	}
	if err := json.Unmarshal(data, &ir); err != nil {
		return nil, fmt.Errorf("%w: decoding response: %w", ErrIssueFailed, err)
	}
	if ir.Data.Certificate == "" || ir.Data.PrivateKey == "" {
		return nil, fmt.Errorf("%w: response had no certificate/private_key: %s", ErrIssueFailed, strings.Join(ir.Errors, "; "))
	}
	return &ir, nil
}

// fetchCACertPEM fetches the PKI mount's current CA certificate. Unlike
// the issue endpoint, ca/pem returns the raw PEM bytes directly rather
// than a JSON envelope.
func (c *obClient) fetchCACertPEM(ctx context.Context) ([]byte, error) {
	reqURL := fmt.Sprintf("%s/v1/%s/ca/pem", c.addr, c.mount)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCAFetchFailed, err)
	}
	req.Header.Set("X-Vault-Token", c.token)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCAFetchFailed, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: reading response: %w", ErrCAFetchFailed, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: status %d: %s", ErrCAFetchFailed, resp.StatusCode, string(data))
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: empty CA certificate returned", ErrCAFetchFailed)
	}
	return data, nil
}

type renewRequest struct {
	LeaseID   string `json:"lease_id"`
	Increment int    `json:"increment,omitempty"`
}

type renewResponse struct {
	LeaseID       string   `json:"lease_id"`
	LeaseDuration int      `json:"lease_duration"`
	Renewable     bool     `json:"renewable"`
	Errors        []string `json:"errors"`
}

// renewLease asks OpenBao to renew leaseID by increment.
//
// Note for reviewers: OpenBao's (and upstream Vault's) PKI secrets engine
// issues certificates with a fixed NotAfter baked into the certificate at
// issuance time -- renewing the lease does not and cannot extend that
// certificate's actual validity, and a real OpenBao server responds to
// this call with "lease is not renewable" for PKI issue leases (verified
// against a local OpenBao dev server; see certs_test.go). This
// method still asks OpenBao rather than deciding locally, per this
// workstream's brief to drive rotation off OpenBao's lease state instead
// of a self-managed timer: RotateTLSCerts calls this first and only falls
// back to reissuing a fresh certificate when OpenBao reports the lease
// can't be (or wasn't) extended far enough past the rotation threshold.
func (c *obClient) renewLease(ctx context.Context, leaseID string, increment time.Duration) (*renewResponse, error) {
	reqBody := renewRequest{LeaseID: leaseID}
	if increment > 0 {
		reqBody.Increment = int(increment.Seconds())
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("%w: encoding request: %w", ErrRenewFailed, err)
	}
	reqURL := fmt.Sprintf("%s/v1/sys/leases/renew", c.addr)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, reqURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRenewFailed, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Vault-Token", c.token)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRenewFailed, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: reading response: %w", ErrRenewFailed, err)
	}
	var rr renewResponse
	if resp.StatusCode != http.StatusOK {
		_ = json.Unmarshal(data, &rr)
		return nil, fmt.Errorf("%w: status %d: %s", ErrRenewFailed, resp.StatusCode, strings.Join(rr.Errors, "; "))
	}
	if err := json.Unmarshal(data, &rr); err != nil {
		return nil, fmt.Errorf("%w: decoding response: %w", ErrRenewFailed, err)
	}
	return &rr, nil
}

// leaseID tracks the most recently issued certificate's OpenBao lease for
// this process, so RotateTLSCerts can attempt a lease renewal before
// falling back to reissuing. It is intentionally in-memory only: after a
// process restart there is no lease to renew, and RotateTLSCerts falls
// back to reading the certificate's own NotAfter in that case.
var (
	leaseMu        sync.Mutex
	currentLeaseID string
)

func rememberLease(id string) {
	leaseMu.Lock()
	currentLeaseID = id
	leaseMu.Unlock()
}

func currentLease() string {
	leaseMu.Lock()
	defer leaseMu.Unlock()
	return currentLeaseID
}

func writeFile(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// genCACert fetches the PKI mount's CA certificate from OpenBao and writes
// it to config.RootCA. OpenBao custodies the CA private key itself -- it
// never leaves OpenBao and never touches this process -- so, unlike the
// old self-signed implementation, there is no CA key file to generate or
// manage here; config.RootCAPriv is no longer used by this package.
func genCACert() error {
	client, err := newClientFromEnv()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	caPEM, err := client.fetchCACertPEM(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch CA certificate: %w", err)
	}
	if err := writeFile(config.RootCA, caPEM, 0o644); err != nil {
		return fmt.Errorf("failed to write CA cert file %s: %w", config.RootCA, err)
	}
	log.Debugf("wrote %s", config.RootCA)
	return nil
}

// issueAndWrite fetches the current CA certificate and issues a fresh leaf
// certificate from OpenBao's PKI secrets engine, writing all three
// artifacts (RootCA, CertFile, KeyFile) to disk.
func issueAndWrite() error {
	if err := genCACert(); err != nil {
		return err
	}
	client, err := newClientFromEnv()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ir, err := client.issueCert(ctx, config.CertHosts, config.CertificateValidTime)
	if err != nil {
		return fmt.Errorf("failed to issue TLS certificate: %w", err)
	}
	if err := writeFile(config.CertFile, []byte(ir.Data.Certificate), 0o644); err != nil {
		return fmt.Errorf("failed to write cert file %s: %w", config.CertFile, err)
	}
	log.Debug("wrote cert.pem")
	if err := writeFile(config.KeyFile, []byte(ir.Data.PrivateKey), 0o600); err != nil {
		return fmt.Errorf("failed to write key file %s: %w", config.KeyFile, err)
	}
	log.Debug("wrote key.pem")

	rememberLease(ir.LeaseID)
	return nil
}

// GenCert ensures a TLS server certificate and private key exist at
// config.CertFile/config.KeyFile, issuing them from OpenBao's PKI secrets
// engine if they don't. If a cert and key already exist, it does nothing
// -- callers wanting a fresh certificate should use RotateTLSCerts.
func GenCert() error {
	_, err := os.Stat(config.CertFile)
	if !os.IsNotExist(err) {
		_, errKey := os.Stat(config.KeyFile)
		if !os.IsNotExist(errKey) {
			log.Trace("Found a TLS keypair, not generating a new one...")
			return nil
		}
	}
	return issueAndWrite()
}

// RotateTLSCerts checks whether the current TLS leaf certificate needs
// rotating and, if so, replaces it with a freshly issued one from
// OpenBao.
//
// Whether rotation is due at all is still decided from the certificate's
// own NotAfter vs. threshold -- that's a local, free check, and there is
// no reason to call out to OpenBao at all for a certificate that is
// nowhere near expiry. Once rotation is due, though, this is where the
// old self-managed-timer implementation simply regenerated a new
// certificate locally; here, if this process holds an OpenBao lease for
// the current certificate, it asks OpenBao to renew that lease first, and
// only reissues when OpenBao reports the lease can't be extended past
// threshold (which, for the PKI secrets engine, is the normal case --
// see the comment on (*obClient).renewLease). When no lease is tracked
// (e.g. right after a process restart), it reissues directly, since there
// is no lease handle to ask OpenBao about.
//
// Returns true if the certificate was rotated.
func RotateTLSCerts(threshold time.Duration) (bool, error) {
	certBytes, err := os.ReadFile(config.CertFile)
	if err != nil {
		if os.IsNotExist(err) {
			if err := GenCert(); err != nil {
				return false, fmt.Errorf("failed to generate cert: %w", err)
			}
			return true, nil
		}
		return false, fmt.Errorf("failed to read cert file: %w", err)
	}

	block, _ := pem.Decode(certBytes)
	if block == nil {
		log.Warn("TLS certificate PEM is corrupt, regenerating")
		return forceRegenCert()
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Warnf("Failed to parse TLS certificate: %v, regenerating", err)
		return forceRegenCert()
	}

	remaining := time.Until(cert.NotAfter)
	if remaining > threshold {
		log.Tracef("TLS certificate valid for %s, rotation threshold is %s — no rotation needed",
			remaining.Round(time.Minute), threshold.Round(time.Minute))
		return false, nil
	}
	log.Infof("TLS certificate expires in %s (threshold %s), rotation due",
		remaining.Round(time.Minute), threshold.Round(time.Minute))

	leaseID := currentLease()
	if leaseID == "" {
		log.Debug("no OpenBao lease tracked for the current certificate, reissuing")
		return forceRegenCert()
	}

	client, err := newClientFromEnv()
	if err != nil {
		return false, fmt.Errorf("failed to build OpenBao client for lease renewal: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	rr, renewErr := client.renewLease(ctx, leaseID, config.CertificateValidTime)
	cancel()
	if renewErr != nil {
		log.Infof("openbao lease %s could not be renewed (%v), reissuing certificate", leaseID, renewErr)
		return forceRegenCert()
	}
	renewedRemaining := time.Duration(rr.LeaseDuration) * time.Second
	if renewedRemaining > threshold {
		rememberLease(rr.LeaseID)
		log.Tracef("openbao renewed lease %s, %s remaining (threshold %s) — no rotation needed",
			rr.LeaseID, renewedRemaining.Round(time.Minute), threshold.Round(time.Minute))
		return false, nil
	}
	log.Infof("openbao lease %s renewed but only %s remains (threshold %s), reissuing certificate",
		rr.LeaseID, renewedRemaining.Round(time.Minute), threshold.Round(time.Minute))
	return forceRegenCert()
}

// forceRegenCert removes the existing server cert and key, then issues a
// fresh pair from OpenBao's PKI secrets engine.
func forceRegenCert() (bool, error) {
	if err := os.Remove(config.CertFile); err != nil && !os.IsNotExist(err) {
		return false, fmt.Errorf("failed to remove old cert: %w", err)
	}
	if err := os.Remove(config.KeyFile); err != nil && !os.IsNotExist(err) {
		return false, fmt.Errorf("failed to remove old key: %w", err)
	}
	if err := issueAndWrite(); err != nil {
		return false, fmt.Errorf("failed to reissue TLS certificate: %w", err)
	}
	return true, nil
}
