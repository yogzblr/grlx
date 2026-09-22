// Package pxc opens the shared GORM handle farmer's PKI, props/facts, and
// RBAC stores use against the `farmer` schema in the Percona XtraDB
// Cluster (see docs/design/cloudxp-machine-manager-api-design.md §5.1:
// farmer owns farmer.* with ALL grants). cmd/farmer/main.go calls OpenDB
// once at startup and hands the resulting *gorm.DB to each owning
// package's own SetDB (props.SetDB, pki.SetDB, rbac.SetDB) — mirroring
// the injection pattern internal/saasapi/db.go already uses for the
// `saas` schema — so each package reads through it on every call, with no
// in-memory cache layered on top by any caller.
package pxc

import (
	"fmt"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// OpenDB opens a GORM connection to the farmer schema and migrates the
// given models. Every farmer-schema owning package (props, pki, rbac)
// passes its own models so a single call from cmd/farmer/main.go can
// migrate the whole schema through one connection.
func OpenDB(dsn string, models ...any) (*gorm.DB, error) {
	if dsn == "" {
		return nil, fmt.Errorf("pxc: empty DSN")
	}
	d, err := gorm.Open(mysql.Open(dsn), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Warn),
	})
	if err != nil {
		return nil, fmt.Errorf("pxc: opening farmer schema: %w", err)
	}
	if len(models) > 0 {
		if err := d.AutoMigrate(models...); err != nil {
			return nil, fmt.Errorf("pxc: migrating farmer schema: %w", err)
		}
	}
	return d, nil
}
