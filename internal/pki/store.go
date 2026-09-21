package pki

// PXC-backed storage for sprout NKey lifecycle state (unaccepted / denied /
// rejected / accepted). Previously each state was a directory under
// config.FarmerPKI/sprouts/<state>/<sproutID>, with the file's content
// holding the raw NKey and its directory holding the sprout's current
// state — so an Accept/Deny/Reject/Unaccept call was an os.Rename, visible
// only to whichever farmer replica had that directory on local disk. That's
// the same cross-replica divergence class as props/store.go (see
// docs/design/grlx-fork-roadmap.md workstream A): a sprout accepted on one
// replica could still show up as unaccepted to a request served by
// another. This file reads and writes straight through to the shared
// `farmer` schema in PXC on every call, so every replica agrees on a given
// sprout's state.
//
// tenant_id scoping (workstream A.1, FLAG FOR SECURITY REVIEW): every
// query here includes tenant_id in the same WHERE clause as sprout_id,
// following the same tenantID() seam as internal/props (see its store.go
// doc comment for why this resolves to config.FarmerOrganization rather
// than a per-request value today).

import (
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/gogrlx/grlx/v2/internal/config"
)

// nkeyRow is the `pki_nkeys` table in the farmer schema. SproutID is part
// of the primary key (not just NKey), so a given sprout ID can hold
// exactly one lifecycle state at a time per tenant — the file-based store
// only enforced that by convention (each Accept/Deny/Reject/Unaccept call
// only ever wrote to one state directory), this makes it structural.
type nkeyRow struct {
	TenantID string `gorm:"column:tenant_id;primaryKey;size:191"`
	SproutID string `gorm:"column:sprout_id;primaryKey;size:253"`
	NKey     string `gorm:"column:nkey;size:191;not null;index"`
	State    string `gorm:"column:state;size:32;not null;index"`
}

func (nkeyRow) TableName() string { return "pki_nkeys" }

const (
	stateUnaccepted = "unaccepted"
	stateAccepted   = "accepted"
	stateDenied     = "denied"
	stateRejected   = "rejected"
)

// tenantRow is the `pki_tenants` table: the durable, replica-shared record
// of which tenants this farmer has provisioned a NATS Account for (see
// tenant.go's ProvisionTenant/DeprovisionTenant). This is what makes
// "FarmerOrganization" dynamic per workstream E — previously the only
// tenant Account this farmer would ever mint was the single one named by
// the static config.FarmerOrganization string, decided once at boot. A row
// here means "the Account exists and, unless Deleted, the bus resolver
// should trust it" — see ConfigureNats (nats.go), which seeds the resolver
// from every non-deleted row here in addition to the legacy single-tenant
// seam's own Account.
type tenantRow struct {
	ID        string `gorm:"column:id;primaryKey;size:191"`
	Name      string `gorm:"column:name;size:255;not null"`
	Deleted   bool   `gorm:"column:deleted;not null;default:false;index"`
	CreatedAt int64  `gorm:"column:created_at;not null"`
}

func (tenantRow) TableName() string { return "pki_tenants" }

// Models returns the GORM models this package owns, for callers assembling
// a single AutoMigrate call across the whole farmer schema (see
// cmd/farmer/main.go and internal/pxc).
func Models() []any { return []any{&nkeyRow{}, &tenantRow{}} }

// db is the shared farmer-schema GORM handle. Nil until SetDB is called.
var db *gorm.DB

// SetDB installs the GORM handle this package reads and writes through.
// Call once at startup, after internal/pxc.OpenDB.
func SetDB(d *gorm.DB) { db = d }

// tenantID resolves the current tenant scope for every query in this
// package. See internal/props/store.go's doc comment for why this isn't
// yet a per-request value.
func tenantID() string {
	if config.FarmerOrganization != "" {
		return config.FarmerOrganization
	}
	return "default"
}

// currentTenantID is an alias for tenantID(), for callers in tenant.go
// that take an explicit tenant ID as a same-named parameter (shadowing the
// package-level tenantID function within that scope) but still need to
// compare against or fall back to the current-tenant seam's value.
func currentTenantID() string { return tenantID() }

func findNKeyRow(id string) (*nkeyRow, error) {
	if !IsValidSproutID(id) {
		return nil, ErrSproutIDInvalid
	}
	var row nkeyRow
	if err := db.Where("tenant_id = ? AND sprout_id = ?", tenantID(), id).First(&row).Error; err != nil {
		return nil, ErrSproutIDNotFound
	}
	return &row, nil
}

// upsertNKeyRow inserts a new sprout NKey row, or updates its nkey/state in
// place if a row for (tenant, sproutID) already exists.
func upsertNKeyRow(row nkeyRow) error {
	return db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "tenant_id"}, {Name: "sprout_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"nkey", "state"}),
	}).Create(&row).Error
}

func setState(id, state string) error {
	return db.Model(&nkeyRow{}).
		Where("tenant_id = ? AND sprout_id = ?", tenantID(), id).
		Update("state", state).Error
}

// SproutIDForNKey looks up the accepted sprout ID owning nkey, for the
// current tenant. Used by internal/heartbeat to map a NATS connection's
// authenticated pubkey (see $SYS.ACCOUNT.*.CONNECT/DISCONNECT's
// ClientInfo.User) back to a sprout ID.
func SproutIDForNKey(nkey string) (string, error) {
	var row nkeyRow
	err := db.Where("tenant_id = ? AND nkey = ? AND state = ?", tenantID(), nkey, stateAccepted).First(&row).Error
	if err != nil {
		return "", ErrSproutIDNotFound
	}
	return row.SproutID, nil
}

// SproutIDAndTenantForNKey looks up the accepted sprout ID and its owning
// tenant for nkey, searching across every tenant rather than just the
// current one. This backs Enroll's idempotency check (enroll.go): at that
// point in the enrollment flow the caller's tenant isn't known yet (that
// only comes from decoding the join token, the next step) but nkey_pub
// is — and since NKeys are 256-bit Ed25519 public keys a caller generates
// itself, a match here unambiguously identifies both the sprout and its
// tenant regardless of which tenant issued the join token this replay is
// skipping. FLAG FOR SECURITY REVIEW: this is the one nkey lookup in this
// package that's deliberately NOT tenant-scoped — see enroll.go for why
// that's required here rather than a gap.
func SproutIDAndTenantForNKey(nkey string) (tenantID, sproutID string, err error) {
	var row nkeyRow
	dbErr := db.Where("nkey = ? AND state = ?", nkey, stateAccepted).First(&row).Error
	if dbErr != nil {
		return "", "", ErrSproutIDNotFound
	}
	return row.TenantID, row.SproutID, nil
}

// findNKeyRowInTenant is findNKeyRow parameterized by an explicit tenant
// rather than the package's current-tenant seam — used by the enrollment
// path (enroll.go), which has a real per-request tenant (the enrollment
// key's own TenantID) available.
func findNKeyRowInTenant(tenantID, id string) (*nkeyRow, error) {
	if !IsValidSproutID(id) {
		return nil, ErrSproutIDInvalid
	}
	var row nkeyRow
	if err := db.Where("tenant_id = ? AND sprout_id = ?", tenantID, id).First(&row).Error; err != nil {
		return nil, ErrSproutIDNotFound
	}
	return &row, nil
}

// NKeyExistsInTenant is NKeyExists scoped to an explicit tenant instead of
// the package's current-tenant seam. See findNKeyRowInTenant.
func NKeyExistsInTenant(tenantID, id, nkey string) (registered bool, matches bool) {
	row, err := findNKeyRowInTenant(tenantID, id)
	if err != nil {
		return false, false
	}
	return true, row.NKey == nkey
}

// upsertTenantRow inserts or (if already present, undeleting it) updates
// the pki_tenants row for id/name. Idempotent — see ProvisionTenant.
func upsertTenantRow(row tenantRow) error {
	return db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns([]string{"name", "deleted"}),
	}).Create(&row).Error
}

// markTenantDeleted flags a tenant as deprovisioned without removing its
// row — DeprovisionTenant (tenant.go) still needs it around afterward
// (e.g. to refuse re-provisioning silently resurrecting a deleted tenant
// under a stale Account signing key without an explicit re-provision).
func markTenantDeleted(id string) error {
	return db.Model(&tenantRow{}).Where("id = ?", id).Update("deleted", true).Error
}

// getTenantRow looks up a single tenant registry row by ID, including
// deleted ones (callers that care about Deleted check it themselves).
func getTenantRow(id string) (*tenantRow, error) {
	var row tenantRow
	if err := db.Where("id = ?", id).First(&row).Error; err != nil {
		return nil, ErrTenantNotFound
	}
	return &row, nil
}
