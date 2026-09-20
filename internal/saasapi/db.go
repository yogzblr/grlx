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
// tables this package owns (tenants, provisioning_jobs, enrollment_keys —
// design doc §4.2). It never touches the `farmer` schema.
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
	if err := db.AutoMigrate(&Tenant{}, &ProvisioningJob{}, &EnrollmentKey{}); err != nil {
		return nil, fmt.Errorf("saasapi: migrating saas schema: %w", err)
	}
	return db, nil
}
