package natsapi

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/gogrlx/grlx/v2/internal/config"
	"github.com/gogrlx/grlx/v2/internal/objectstore"
)

// RecipeInfo represents a recipe file in the listing.
type RecipeInfo struct {
	// Name is the dot-notation recipe name (e.g., "webserver.nginx").
	Name string `json:"name"`
	// Path is the object key relative to the recipe root.
	Path string `json:"path"`
	// Size is the file size in bytes.
	Size int64 `json:"size"`
}

// RecipeContent represents the full content of a recipe file.
type RecipeContent struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Content string `json:"content"`
	Size    int64  `json:"size"`
}

// recipeStore is the object-storage backend recipes are read from — see
// docs/design/grlx-master-plan.md Phase 1 and internal/cook/store.go's
// identical seam. Set once at startup via SetRecipeStore, alongside
// cook.SetStore, with the same *objectstore.Store instance.
var recipeStore *objectstore.Store

// SetRecipeStore installs the object-storage backend this package reads
// recipes from.
func SetRecipeStore(s *objectstore.Store) { recipeStore = s }

func handleRecipesList(_ json.RawMessage) (any, error) {
	if recipeStore == nil {
		return nil, fmt.Errorf("recipe store not configured")
	}
	recipeDir := config.RecipeDir
	if recipeDir == "" {
		return nil, fmt.Errorf("recipe directory not configured")
	}

	ctx := context.Background()
	ext := "." + config.GrlxExt
	prefix := strings.TrimSuffix(recipeDir, "/") + "/"

	keys, err := recipeStore.List(ctx, prefix)
	if err != nil {
		return nil, fmt.Errorf("error listing recipes: %w", err)
	}

	var recipes []RecipeInfo
	for _, key := range keys {
		if !strings.HasSuffix(key, ext) {
			continue
		}
		relPath := strings.TrimPrefix(key, prefix)

		// Convert file path to dot-notation recipe name:
		// "webserver/nginx.grlx" -> "webserver.nginx"
		name := strings.TrimSuffix(relPath, ext)
		name = strings.ReplaceAll(name, "/", ".")

		size := int64(-1)
		if s, statErr := recipeStore.Size(ctx, key); statErr == nil {
			size = s
		}

		recipes = append(recipes, RecipeInfo{
			Name: name,
			Path: relPath,
			Size: size,
		})
	}

	if recipes == nil {
		recipes = []RecipeInfo{}
	}
	return map[string][]RecipeInfo{"recipes": recipes}, nil
}

func handleRecipesGet(params json.RawMessage) (any, error) {
	var req struct {
		Name string `json:"name"`
		ID   string `json:"id"`
	}
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	recipeName := req.Name
	if recipeName == "" {
		recipeName = req.ID
	}
	if recipeName == "" {
		return nil, fmt.Errorf("recipe name is required")
	}
	if recipeStore == nil {
		return nil, fmt.Errorf("recipe store not configured")
	}
	recipeDir := config.RecipeDir
	if recipeDir == "" {
		return nil, fmt.Errorf("recipe directory not configured")
	}

	// Convert dot-notation to an object key. Object storage has no
	// directory-traversal concept the way a local filesystem does — a
	// crafted name containing ".." just names a distinct, harmless key,
	// never a path outside the bucket — so unlike the old local-disk
	// version, no separate path-traversal check is needed here.
	relPath := strings.ReplaceAll(recipeName, ".", "/") + "." + config.GrlxExt
	key := filepath.Join(recipeDir, relPath)

	ctx := context.Background()
	content, err := recipeStore.Get(ctx, key)
	if err != nil {
		if objectstore.IsNotExist(err) {
			return nil, fmt.Errorf("recipe not found: %s", recipeName)
		}
		return nil, fmt.Errorf("cannot read recipe: %w", err)
	}

	return RecipeContent{
		Name:    recipeName,
		Path:    relPath,
		Content: string(content),
		Size:    int64(len(content)),
	}, nil
}
