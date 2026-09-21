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

// Models returns the GORM models this package owns, for callers assembling
// a single AutoMigrate call across the whole farmer schema (see
// cmd/farmer/main.go and internal/pxc).
func Models() []any { return []any{&nkeyRow{}, &sproutBoxKeyRow{}} }

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
