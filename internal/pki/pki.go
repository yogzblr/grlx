package pki

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	log "github.com/gogrlx/grlx/v2/internal/log"

	"github.com/gogrlx/grlx/v2/internal/config"
)

type PubKeyType int

const (
	SproutPubNKey PubKeyType = iota
	FarmerPubNKey
	CliPubNKey
)

var sproutMatcher *regexp.Regexp

func init() {
	sproutMatcher = regexp.MustCompile(`^[0-9a-z\.][-0-9_a-z\.]*$`)
}

// SetupPKIFarmer ensures the farmer's PKI directory exists. Sprout NKey
// lifecycle state itself now lives in PXC (see store.go) — this directory
// is still needed for the nats-auth trust-chain material (jwtauth.go) and
// the TLS certificate files (config.CertFile/KeyFile) that live under it.
func SetupPKIFarmer() {
	FarmerPKI := config.FarmerPKI
	_, err := os.Stat(FarmerPKI)
	if os.IsNotExist(err) {
		err = os.MkdirAll(FarmerPKI, os.ModePerm)
		if err != nil {
			if os.IsPermission(err) {
				log.Fatalf("insufficient permissions to create PKI directory %s: %v", FarmerPKI, err)
			}
			log.Fatalf("failed to create PKI directory %s: %v", FarmerPKI, err)
		}
	}
}

func SetupPKISprout() {
	SproutPKI := config.SproutPKI
	_, err := os.Stat(SproutPKI)
	if err == nil {
		return
	}
	if os.IsNotExist(err) {
		err = os.MkdirAll(SproutPKI, os.ModePerm)
		if err != nil {
			log.Panicf("failed to create sprout PKI directory: %v", err)
		}
	} else {

		log.Panicf("unexpected error checking sprout PKI directory: %v", err)
	}
}

// rules on sprout ids:
// must be unique
// if multiple sprouts claim the same id, the first one gets the id,
// following sprouts get id_n where n is their place in the queue
// sprout ids must be valid *nix hostnames: [0-9a-z\.][-0-9a-z\.]
// should automatically convert any found underscores to hyphens, unless
// the hostname starts with an underscore, in which case it is removed.
// maximum length is 253 characters
// trailing dots are not allowed

func createSproutID() string {
	id, err := os.Hostname()
	if err != nil {
		// Fall back to "unknown" if hostname cannot be determined
		log.Errorf("failed to get hostname for sprout ID: %v", err)
		id = "unknown"
	}
	id = strings.ToLower(id)
	id = strings.ReplaceAll(id, "_", "-")
	id = strings.TrimPrefix(id, "-")
	return id
}

func IsValidSproutID(id string) bool {
	if len(id) > 253 {
		return false
	}
	if strings.HasPrefix(id, "_") {
		return false
	}
	if strings.HasPrefix(id, "-") {
		return false
	}
	if strings.HasSuffix(id, ".") {
		return false
	}
	if !sproutMatcher.MatchString(id) {
		return false
	}

	return true
}

func AcceptNKey(id string) error {
	defer func() {
		if err := ReloadNKeys(); err != nil {
			log.Errorf("failed to reload NATS auth for accepted sprout %s: %v", id, err)
		}
	}()
	base := strings.SplitN(id, "_", 2)[0]
	if !IsValidSproutID(base) {
		return ErrSproutIDInvalid
	}
	row, err := findNKeyRow(id)
	if err != nil {
		return err
	}
	if len(strings.SplitN(id, "_", 2)) > 1 {
		DeleteNKey(base)
	}
	if id == base && row.State == stateAccepted {
		return ErrAlreadyAccepted
	}
	return db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("tenant_id = ? AND sprout_id = ?", tenantID(), id).Delete(&nkeyRow{}).Error; err != nil {
			return err
		}
		return tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "tenant_id"}, {Name: "sprout_id"}},
			DoUpdates: clause.AssignmentColumns([]string{"nkey", "state"}),
		}).Create(&nkeyRow{TenantID: tenantID(), SproutID: base, NKey: row.NKey, State: stateAccepted}).Error
	})
}

func DeleteNKey(id string) error {
	defer func() {
		if err := ReloadNKeys(); err != nil {
			log.Errorf("failed to reload NATS auth for deleted sprout %s: %v", id, err)
		}
	}()
	if !IsValidSproutID(id) {
		return ErrSproutIDInvalid
	}
	res := db.Where("tenant_id = ? AND sprout_id = ?", tenantID(), id).Delete(&nkeyRow{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrSproutIDNotFound
	}
	return nil
}

func DenyNKey(id string) error {
	defer func() {
		if err := ReloadNKeys(); err != nil {
			log.Errorf("failed to reload NATS auth for denied sprout %s: %v", id, err)
		}
	}()
	if !IsValidSproutID(id) {
		return ErrSproutIDInvalid
	}
	row, err := findNKeyRow(id)
	if err != nil {
		return err
	}
	if row.State == stateDenied {
		return ErrAlreadyDenied
	}
	return setState(id, stateDenied)
}

func UnacceptNKey(id string, nkey string) error {
	defer func() {
		if err := ReloadNKeys(); err != nil {
			log.Errorf("failed to reload NATS auth for unaccepted sprout %s: %v", id, err)
		}
	}()
	if !IsValidSproutID(id) {
		return ErrSproutIDInvalid
	}
	row, err := findNKeyRow(id)
	if nkey != "" && err == ErrSproutIDNotFound {
		return upsertNKeyRow(nkeyRow{TenantID: tenantID(), SproutID: id, NKey: nkey, State: stateUnaccepted})
	}
	if err != nil {
		return err
	}
	if row.State == stateUnaccepted {
		return ErrAlreadyUnaccepted
	}
	return setState(id, stateUnaccepted)
}

func GetNKeysByType(set string) KeySet {
	return getNKeysByTypeForTenant(tenantID(), set)
}

// getNKeysByTypeForTenant is GetNKeysByType scoped to an explicit tenant
// instead of the package's current-tenant seam — used by tenant.go's
// per-tenant sync path (syncTenantSprouts).
func getNKeysByTypeForTenant(tenantID, set string) KeySet {
	keySet := KeySet{}
	keySet.Sprouts = []KeyManager{}
	switch set {
	case "unaccepted":
		fallthrough
	case "accepted":
		fallthrough
	case "denied":
		fallthrough
	case "rejected":
		// continue execution below default case
	default:
		return keySet
	}
	var rows []nkeyRow
	db.Where("tenant_id = ? AND state = ?", tenantID, set).Find(&rows)
	for _, r := range rows {
		keySet.Sprouts = append(keySet.Sprouts, KeyManager{SproutID: r.SproutID})
	}
	return keySet
}

func ListNKeysByType() KeysByType {
	var allKeys KeysByType
	allKeys.Accepted = GetNKeysByType("accepted")
	allKeys.Denied = GetNKeysByType("denied")
	allKeys.Rejected = GetNKeysByType("rejected")
	allKeys.Unaccepted = GetNKeysByType("unaccepted")
	return allKeys
}

func RejectNKey(id string, nkey string) error {
	defer func() {
		if err := ReloadNKeys(); err != nil {
			log.Errorf("failed to reload NATS auth for rejected sprout %s: %v", id, err)
		}
	}()
	if !IsValidSproutID(id) {
		return ErrSproutIDInvalid
	}
	row, err := findNKeyRow(id)
	if nkey != "" && err == ErrSproutIDNotFound {
		return upsertNKeyRow(nkeyRow{TenantID: tenantID(), SproutID: id, NKey: nkey, State: stateRejected})
	}
	if err != nil {
		return err
	}
	if row.State == stateRejected {
		return ErrAlreadyRejected
	}
	return setState(id, stateRejected)
}

func GetNKey(id string) (string, error) {
	row, err := findNKeyRow(id)
	if err != nil {
		return "", err
	}
	return row.NKey, nil
}

func NKeyExists(id string, nkey string) (Registered bool, Matches bool) {
	row, err := findNKeyRow(id)
	if err != nil {
		return false, false
	}
	return true, row.NKey == nkey
}

func FetchRootCA(filename string) error {
	RootCA := filename
	_, err := os.Stat(RootCA)
	if err == nil {
		return err
	}
	if !os.IsNotExist(err) {
		return err
	}
	file, err := os.Create(RootCA)
	if err != nil {
		return err
	}
	defer file.Close()
	// InsecureSkipVerify is intentional: this is the TLS bootstrap path where
	// the sprout fetches the farmer's root CA for the first time. There is no
	// trusted certificate to verify against yet.
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // TLS bootstrap
	}
	client := &http.Client{Transport: tr, Timeout: time.Second * 10}
	r, err := client.Get(fmt.Sprintf("https://%s:%s/auth/cert/", config.FarmerInterface, config.FarmerAPIPort))
	if err != nil {
		os.Remove(RootCA)
		return err
	}
	defer r.Body.Close()
	_, err = io.Copy(file, r.Body)
	if err != nil {
		os.Remove(RootCA)
	}
	return err
}

func RootCACached(binary string) bool {
	var RootCA string
	switch binary {
	case "grlx":
		RootCA = config.GrlxRootCA
	case "sprout":
		RootCA = config.SproutRootCA
	}
	_, err := os.Stat(RootCA)
	return err == nil
}

var (
	nkeyClient   *http.Client
	nkeyClientMu sync.RWMutex
)

func LoadRootCA(binary string) error {
	client := &http.Client{}
	var RootCA string
	switch binary {
	case "grlx":
		RootCA = config.GrlxRootCA
	case "sprout":
		RootCA = config.SproutRootCA
		FetchRootCA(RootCA)
	}
	certPool := x509.NewCertPool()
	rootPEM, err := os.ReadFile(RootCA)
	if err != nil || rootPEM == nil {
		return err
	}
	ok := certPool.AppendCertsFromPEM(rootPEM)
	if !ok {
		log.Errorf("nats: failed to parse root certificate from %q", RootCA)
		return ErrCannotParseRootCA
	}
	var nkeyTransport http.RoundTripper = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			RootCAs:    certPool,
			MinVersion: tls.VersionTLS12,
		},
	}
	client.Transport = nkeyTransport
	client.Timeout = time.Second * 10
	nkeyClientMu.Lock()
	nkeyClient = client
	nkeyClientMu.Unlock()
	return nil
}

func PutNKey(id string) error {
	nkey, err := GetPubNKey(SproutPubNKey)
	if err != nil {
		return err
	}
	keySub := KeySubmission{NKey: nkey, SproutID: id}

	jw, err := json.Marshal(keySub)
	if err != nil {
		return fmt.Errorf("failed to marshal key submission: %w", err)
	}
	nkeyClientMu.RLock()
	client := nkeyClient
	nkeyClientMu.RUnlock()
	if client == nil {
		return ErrNKeyClientNotReady
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()
	url := config.FarmerURL + "/pki/putnkey"
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewBuffer(jw))
	if err != nil {
		return fmt.Errorf("failed to build NKey submission request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to submit NKey: %w", err)
	}
	resp.Body.Close()
	return nil
}

func GetPubNKey(keyType PubKeyType) (string, error) {
	var pubFile string
	switch keyType {
	case SproutPubNKey:
		pubFile = config.NKeySproutPubFile
	case FarmerPubNKey:
		pubFile = config.NKeyFarmerPubFile
		// case CliPubNKey:
		//	pubFile = config.NKeyGrlxPubFile
	}
	pubKeyBytes, err := os.ReadFile(pubFile)
	if err != nil {
		return "", err
	}
	return string(pubKeyBytes), nil
}

func GetSproutID() string {
	SproutID := config.SproutID
	if SproutID == "" {
		SproutID = createSproutID()
		config.SetSproutID(SproutID)
	}
	return SproutID
}
