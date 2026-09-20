package cook

import "github.com/gogrlx/grlx/v2/internal/objectstore"

// store is the object-storage backend recipes are read from — see
// docs/design/grlx-master-plan.md Phase 1: farmer's local-disk recipe
// tree (config.RecipeDir/GRLX_RECIPE_DIR) doesn't survive horizontal
// scaling, since any replica needs to be able to serve any recipe. Git
// remains the source of truth; this package only reads what's already
// been synced into the bucket.
var store *objectstore.Store

// SetStore installs the object-storage backend this package reads
// recipes from. Call once at startup, mirroring RegisterNatsConn's
// injection pattern.
func SetStore(s *objectstore.Store) { store = s }
