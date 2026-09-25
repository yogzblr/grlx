package saasapi

import (
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

// newTestDB opens a fresh in-memory, pure-Go (no CGO) sqlite database,
// migrates this package's tables, and installs it as the package-level db
// used by the handlers. Tests in this package are not run in parallel
// with each other because of this shared global.
func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	gdb, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("opening test db: %v", err)
	}
	if err := migrateSchema(gdb); err != nil {
		t.Fatalf("migrating test db: %v", err)
	}
	SetDB(gdb)
	t.Cleanup(func() { SetDB(nil) })
	return gdb
}
