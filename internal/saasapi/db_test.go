package saasapi

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// legacyAssetLink is AssetLink as first committed: a single-column UNIQUE
// on sprout_id and a plain index on tenant_id. Migrating it creates
// exactly the indexes legacyAssetLinkIndexes names.
type legacyAssetLink struct {
	ID       string    `gorm:"column:id;primaryKey;size:32"`
	TenantID string    `gorm:"column:tenant_id;size:32;not null;index"`
	SproutID string    `gorm:"column:sprout_id;size:253;not null;uniqueIndex"`
	AssetID  string    `gorm:"column:asset_id;size:191;not null;uniqueIndex"`
	LinkedAt time.Time `gorm:"column:linked_at;not null"`
}

func (legacyAssetLink) TableName() string { return "asset_links" }

// openIsolatedTestDB opens a sqlite database of its own, deliberately not
// newTestDB's shared-cache one (which other tests reuse), so a legacy
// asset_links schema created here can't leak into them. GORM's logger is
// silenced: these tests expect constraint violations, and each one is
// asserted on directly.
func openIsolatedTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	gdb, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "saas.db")),
		&gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	if err != nil {
		t.Fatalf("opening isolated test db: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, err := gdb.DB(); err == nil {
			sqlDB.Close()
		}
	})
	return gdb
}

func newLink(id, tenantID, sproutID, assetID string) AssetLink {
	return AssetLink{ID: id, TenantID: tenantID, SproutID: sproutID, AssetID: assetID, LinkedAt: time.Now().UTC()}
}

// TestMigrateSchemaFixesLegacySproutUniqueness proves the migration, not
// only the fresh-schema tags: on a database migrated from the old model,
// a second tenant can't link its own "web-01" (the defect), and after
// migrateSchema it can — while (tenant_id, sprout_id) and asset_id stay
// UNIQUE.
func TestMigrateSchemaFixesLegacySproutUniqueness(t *testing.T) {
	gdb := openIsolatedTestDB(t)
	if err := gdb.AutoMigrate(&legacyAssetLink{}); err != nil {
		t.Fatalf("creating legacy schema: %v", err)
	}
	m := gdb.Migrator()
	for _, name := range legacyAssetLinkIndexes {
		if !m.HasIndex(&AssetLink{}, name) {
			t.Fatalf("legacy schema lacks %s; legacyAssetLink no longer matches legacyAssetLinkIndexes", name)
		}
	}

	a := newLink("al_a", "t_a", "web-01", "asset_a")
	b := newLink("al_b", "t_b", "web-01", "asset_b")
	if err := gdb.Create(&a).Error; err != nil {
		t.Fatalf("linking tenant A's web-01: %v", err)
	}
	if err := gdb.Create(&b).Error; err == nil {
		t.Fatal("legacy schema accepted a second tenant's web-01; the defect this migration fixes didn't reproduce")
	}

	// Twice: the second run must find nothing left to drop.
	for i := range 2 {
		if err := migrateSchema(gdb); err != nil {
			t.Fatalf("migrateSchema run %d: %v", i+1, err)
		}
	}
	for _, name := range legacyAssetLinkIndexes {
		if m.HasIndex(&AssetLink{}, name) {
			t.Fatalf("legacy index %s survived migration", name)
		}
	}
	for _, name := range []string{"idx_asset_links_tenant_sprout", "idx_asset_links_asset_id"} {
		if !m.HasIndex(&AssetLink{}, name) {
			t.Fatalf("migrated schema lacks %s", name)
		}
	}

	if err := gdb.Create(&b).Error; err != nil {
		t.Fatalf("after migration, tenant B couldn't link its own web-01: %v", err)
	}
	for name, dup := range map[string]AssetLink{
		"same tenant, same sprout":   newLink("al_c", "t_a", "web-01", "asset_c"),
		"asset_id in another tenant": newLink("al_d", "t_c", "web-02", "asset_a"),
	} {
		if err := gdb.Create(&dup).Error; err == nil {
			t.Fatalf("%s: migrated schema accepted a duplicate", name)
		}
	}
}

// TestMigrateSchemaFreshDatabase: on an empty database, migrateSchema
// creates only the current indexes.
func TestMigrateSchemaFreshDatabase(t *testing.T) {
	gdb := openIsolatedTestDB(t)
	if err := migrateSchema(gdb); err != nil {
		t.Fatalf("migrateSchema: %v", err)
	}
	m := gdb.Migrator()
	for _, name := range legacyAssetLinkIndexes {
		if m.HasIndex(&AssetLink{}, name) {
			t.Fatalf("fresh schema has legacy index %s", name)
		}
	}
	for _, l := range []AssetLink{
		newLink("al_a", "t_a", "web-01", "asset_a"),
		newLink("al_b", "t_b", "web-01", "asset_b"),
	} {
		if err := gdb.Create(&l).Error; err != nil {
			t.Fatalf("linking %s's web-01: %v", l.TenantID, err)
		}
	}
}
