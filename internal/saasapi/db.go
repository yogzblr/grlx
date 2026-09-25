package saasapi

import (
	"fmt"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// db is the package-level GORM handle used by the HTTP handlers, set once
// at startup via SetDB — the same injection pattern natsapi/cook/jobs use
// for their NATS connections (RegisterNatsConn).
var db *gorm.DB

// SetDB installs the GORM handle the handlers use. Call once at startup,
// after OpenDB.
func SetDB(d *gorm.DB) { db = d }

// OpenDB opens a GORM connection to the `saas` schema and migrates the
// tables this package owns (tenants, provisioning_jobs, enrollment_keys,
// asset_links — design doc §4.2). It never writes to the `farmer` schema;
// asset_links.go only reads farmer.pki_nkeys, through the saas service
// account's SELECT grant (§4.1).
func OpenDB(dsn string) (*gorm.DB, error) {
	if dsn == "" {
		return nil, fmt.Errorf("saasapi: empty DSN")
	}
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Warn),
	})
	if err != nil {
		return nil, fmt.Errorf("saasapi: opening saas schema: %w", err)
	}
	if err := migrateSchema(db); err != nil {
		return nil, fmt.Errorf("saasapi: migrating saas schema: %w", err)
	}
	return db, nil
}

// legacyAssetLinkIndexes are indexes that asset_links' earlier GORM tags
// created and its current ones don't. AutoMigrate only ever adds indexes,
// so these would otherwise survive on any database first migrated from
// the older model:
//   - idx_asset_links_sprout_id: a single-column UNIQUE on sprout_id.
//     That's a defect: sprout_id is only unique within a tenant
//     (pki_nkeys' (tenant_id, sprout_id) primary key, pki's
//     resolveEnrollSproutID, heartbeat's (tenant, sproutID) keys), so it
//     would stop a second tenant linking its own same-named sprout.
//     idx_asset_links_tenant_sprout replaces it.
//   - idx_asset_links_tenant_id: a plain index on tenant_id, redundant now
//     that idx_asset_links_tenant_sprout leads with tenant_id.
var legacyAssetLinkIndexes = []string{"idx_asset_links_sprout_id", "idx_asset_links_tenant_id"}

// migrateSchema migrates every table this package owns, then drops
// legacyAssetLinkIndexes where present. Idempotent: on a fresh or
// already-migrated database the drop step finds nothing to do.
func migrateSchema(d *gorm.DB) error {
	if err := d.AutoMigrate(&Tenant{}, &ProvisioningJob{}, &EnrollmentKey{}, &AssetLink{}); err != nil {
		return err
	}
	m := d.Migrator()
	for _, name := range legacyAssetLinkIndexes {
		if !m.HasIndex(&AssetLink{}, name) {
			continue
		}
		if err := m.DropIndex(&AssetLink{}, name); err != nil {
			return fmt.Errorf("dropping legacy index %s: %w", name, err)
		}
	}
	return nil
}
