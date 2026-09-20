package natsapi

import (
	"fmt"
	"os"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/gogrlx/grlx/v2/internal/cook"
	"github.com/gogrlx/grlx/v2/internal/objectstore/objectstoretest"
	"github.com/gogrlx/grlx/v2/internal/pki"
	"github.com/gogrlx/grlx/v2/internal/props"
	"github.com/gogrlx/grlx/v2/internal/rbac"
)

// sharedPKIDB is the package-wide fallback PKI store installed by TestMain.
// setupNatsAPIPKI (pki_handlers_test.go) temporarily swaps in its own
// per-test isolated store and must restore this on cleanup rather than
// nil, since other tests in this binary (e.g. the cohort refresher, which
// calls pki.ListNKeysByType to enumerate sprout IDs) run without calling
// setupNatsAPIPKI at all and still need a non-nil db.
var sharedPKIDB *gorm.DB

// TestMain wires up shared in-memory PXC-backed stores for props, rbac,
// and pki (see their store.go doc comments) — this package's handlers
// read/write through all three directly, so their package-level db
// globals must be set before any test runs.
func TestMain(m *testing.M) {
	propsDB, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		fmt.Println("opening props test db:", err)
		os.Exit(1)
	}
	if err := propsDB.AutoMigrate(props.Models()...); err != nil {
		fmt.Println("migrating props test db:", err)
		os.Exit(1)
	}
	props.SetDB(propsDB)

	rbacDB, err := gorm.Open(sqlite.Open("file:rbac?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		fmt.Println("opening rbac test db:", err)
		os.Exit(1)
	}
	if err := rbacDB.AutoMigrate(rbac.Models()...); err != nil {
		fmt.Println("migrating rbac test db:", err)
		os.Exit(1)
	}
	rbac.SetDB(rbacDB)

	pkiDB, err := gorm.Open(sqlite.Open("file:pki?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		fmt.Println("opening pki test db:", err)
		os.Exit(1)
	}
	if err := pkiDB.AutoMigrate(pki.Models()...); err != nil {
		fmt.Println("migrating pki test db:", err)
		os.Exit(1)
	}
	sharedPKIDB = pkiDB
	pki.SetDB(pkiDB)

	// Recipes now read through internal/objectstore instead of local disk
	// (see internal/cook/store.go) — wire a fake S3 backend into both this
	// package's own recipe handlers and internal/cook (handleCook's
	// SendCookEvent call chain reads through cook's own store, a separate
	// injection point). Individual tests Put() whatever recipe content
	// they need into recipeStore directly; a recipe name that was never
	// seeded simply resolves as not-found, same as it did against an
	// empty local-disk directory before this migration.
	store, closeStore, err := objectstoretest.NewStoreForBinary()
	if err != nil {
		fmt.Println("opening recipe test store:", err)
		os.Exit(1)
	}
	cook.SetStore(store)
	SetRecipeStore(store)

	code := m.Run()
	closeStore()
	os.Exit(code)
}
