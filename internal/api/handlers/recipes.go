// Recipe file serving. This used to be http.FileServer over farmer's
// local-disk basepath (config.RecipeDir) — see
// docs/design/grlx-master-plan.md Phase 1: that doesn't survive
// horizontal scaling, since any core replica needs to be able to serve
// any recipe, so reads now go through object storage instead. Git
// remains the source of truth; syncing a merged commit into the bucket
// this reads from is a deploy-time concern (see
// internal/objectstore's package doc), not something this handler does.
package handlers

import (
	"net/http"
	"strings"

	"github.com/gogrlx/grlx/v2/internal/objectstore"
)

// recipeStore is the object-storage backend GetFile reads from. Set once
// at startup via SetRecipeStore.
var recipeStore *objectstore.Store

// SetRecipeStore installs the object-storage backend GetFile reads from.
func SetRecipeStore(s *objectstore.Store) { recipeStore = s }

// GetFile serves a single recipe file's content, reusing the
// authenticated-download shape of internal/ingredients/file/http's
// client-side provider — a bearer token in the Authorization header (see
// Auth in middleware.go), a GET request, and the raw bytes back — for the
// route sprouts already know as the farmer:// scheme's read path.
func GetFile(w http.ResponseWriter, r *http.Request) {
	key := strings.TrimPrefix(r.URL.Path, "/files/")
	if key == "" || strings.HasSuffix(r.URL.Path, "/") {
		http.NotFound(w, r)
		return
	}
	if recipeStore == nil {
		http.Error(w, "recipe store not configured", http.StatusServiceUnavailable)
		return
	}

	data, err := recipeStore.Get(r.Context(), key)
	if err != nil {
		if objectstore.IsNotExist(err) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "failed to read recipe", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}
