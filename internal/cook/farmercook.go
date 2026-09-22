package cook

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/gogrlx/grlx/v2/internal/log"
	"github.com/google/uuid"
	"gopkg.in/yaml.v3"

	"github.com/gogrlx/grlx/v2/internal/config"
	"github.com/gogrlx/grlx/v2/internal/props"
)

// CookOption configures optional parameters for SendCookEvent.
type CookOption func(*cookOptions)

type cookOptions struct {
	invokedBy  string
	targetStep StepID
}

// WithInvoker sets the pubkey of the user who initiated the cook.
func WithInvoker(pubkey string) CookOption {
	return func(o *cookOptions) {
		o.invokedBy = pubkey
	}
}

// WithTargetStep restricts the cook to a single step (and the transitive
// closure of its requisite dependencies) instead of the whole recipe tree.
// An empty id runs the full recipe.
func WithTargetStep(id StepID) CookOption {
	return func(o *cookOptions) {
		o.targetStep = id
	}
}

func populateFuncMap(tenantID, sproutID string) template.FuncMap {
	v := template.FuncMap{}
	v["props"] = props.GetStringPropFuncForTenant(tenantID, sproutID)
	v["hostname"] = props.GetHostnameFuncForTenant(tenantID, sproutID)

	// Environment variable access.
	v["env"] = os.Getenv

	// String manipulation helpers.
	v["join"] = strings.Join
	v["split"] = strings.Split
	v["replace"] = strings.ReplaceAll
	v["contains"] = strings.Contains
	v["hasPrefix"] = strings.HasPrefix
	v["hasSuffix"] = strings.HasSuffix
	v["trimSpace"] = strings.TrimSpace
	v["upper"] = strings.ToUpper
	v["lower"] = strings.ToLower
	v["title"] = cases.Title(language.English, cases.Compact).String

	// Path helpers.
	v["base"] = filepath.Base
	v["dir"] = filepath.Dir
	v["ext"] = filepath.Ext
	v["cleanPath"] = filepath.Clean

	// Default value: returns fallback if value is empty.
	v["default"] = func(fallback, value string) string {
		if value == "" {
			return fallback
		}
		return value
	}

	// Conditional: ternary-style helper for templates.
	v["ternary"] = func(trueVal, falseVal string, cond bool) string {
		if cond {
			return trueVal
		}
		return falseVal
	}

	// Sprout ID accessor for recipes that need to reference the target sprout.
	v["sproutID"] = func() string { return sproutID }

	return v
}

// SendCookEvent triggers a recipe cook on sproutID, over tenantID's
// dedicated NATS connection (see RegisterFarmerNatsConn) — the sprout's own
// tenant, not necessarily whichever tenant happens to be "current" for the
// process.
func SendCookEvent(tenantID, sproutID string, recipeID RecipeName, JID string, test bool, opts ...CookOption) error {
	basepath := getBasePath()
	includes, err := collectAllIncludes(tenantID, sproutID, basepath, recipeID)
	if err != nil {
		return err
	}
	recipesteps := make(map[string]interface{})
	for _, inc := range includes {
		// load all imported files into recipefile list
		fp, fpErr := ResolveRecipeFilePath(basepath, inc)
		if fpErr != nil {
			log.Errorf("could not find include %s: %v", inc, err)
			return errors.Join(ErrNoRecipe, fpErr)
		}
		f, fpErr := store.Get(context.Background(), fp)
		if fpErr != nil {
			return fpErr
		}
		b, renderErr := renderRecipeTemplate(tenantID, sproutID, fp, f)
		if renderErr != nil {
			return renderErr
		}
		var recipe map[string]interface{}
		marshallErr := yaml.Unmarshal(b, &recipe)
		if marshallErr != nil {
			return marshallErr
		}
		m, loadErr := stepsFromMap(recipe)
		if loadErr != nil {
			return loadErr
		}
		// range over all keys under each recipe ID for matching ingredients
		recipesteps, err = joinMaps(recipesteps, m)
		if err != nil {
			return err
		}
	}
	for id, step := range recipesteps {
		switch s := step.(type) {
		case map[string]interface{}:
			if len(s) != 1 {
				return errors.Join(ErrInvalidFormat, fmt.Errorf("recipe %s must have one directive, but has %d", id, len(s)))
			}

		default:
			return errors.Join(ErrInvalidFormat, fmt.Errorf("recipe %s must me a map[string]interface{} but found %T", id, step))
		}
	}
	steps, err := makeRecipeSteps(recipesteps)
	if err != nil {
		return err
	}
	tree, err := validateRecipeTree(steps)
	if err != nil {
		return err
	}
	validSteps := []Step{}
	for _, step := range tree {
		validSteps = append(validSteps, *step)
	}
	var co cookOptions
	for _, opt := range opts {
		opt(&co)
	}
	// If a target step was requested, prune the tree to that step plus the
	// transitive closure of its requisite dependencies.
	if co.targetStep != "" {
		pruned, pruneErr := PruneToTarget(validSteps, co.targetStep)
		if pruneErr != nil {
			return pruneErr
		}
		validSteps = pruned
	}
	rEnvelope := RecipeEnvelope{
		JobID:     JID,
		Steps:     validSteps,
		Test:      test,
		InvokedBy: co.invokedBy,
	}
	b, _ := json.Marshal(rEnvelope)
	log.Noticef("cooking sprout %s: %s", sproutID, JID)
	farmerConn := farmerConnFor(tenantID)
	if farmerConn == nil {
		return fmt.Errorf("cook: no NATS connection registered for tenant %s", tenantID)
	}
	var ack Ack
	msg, err := farmerConn.Request("grlx.sprouts."+sproutID+".cook", b, 30*time.Second)
	if err != nil {
		return err
	}
	err = json.Unmarshal(msg.Data, &ack)
	if err != nil {
		return err
	}
	if !ack.Acknowledged {
		return errors.New("sprout did not acknowledge recipe")
	}
	if ack.JobID != JID {
		return errors.New("sprout acknowledged recipe but returned wrong JobID")
	}
	return nil
}

func GenerateJobID() string {
	return uuid.New().String()
}

// ResolveRecipeFilePath resolves a dot-notation RecipeName to an object
// key under the object-storage backend (see store.go) recipes are read
// from — basepath is the configured key prefix (config.RecipeDir /
// GRLX_RECIPE_DIR, see getBasePath), not a local filesystem directory.
// The resolution rules (dot-to-slash, try "<name>/init.grlx" before
// "<name>.grlx") are unchanged from the local-disk version; only the
// existence check moved from os.Stat to a bucket lookup. Object storage
// has no directory concept, so the old "resolved path is a directory"
// case (ErrRecipePathIsDirectory) can no longer happen and is gone.
func ResolveRecipeFilePath(basepath string, recipeID RecipeName) (string, error) {
	if store == nil {
		return "", ErrNoRecipe
	}
	ctx := context.Background()
	path := string(recipeID)
	basepath = filepath.Clean(basepath)
	path = filepath.Clean(path)
	path = strings.TrimPrefix(path, basepath)
	path = filepath.Join(basepath, path)
	if strings.HasSuffix(path, "."+config.GrlxExt) {
		// swap out dot notation for slashes, but preserve extension
		path = strings.TrimSuffix(path, "."+config.GrlxExt)
		path = strings.ReplaceAll(path, ".", string(filepath.Separator))
		path = path + "." + config.GrlxExt

		ok, err := store.Exists(ctx, path)
		if err != nil {
			return "", err
		}
		if !ok {
			return "", ErrNoRecipe
		}
		return path, nil
	}
	// at this point, we know the path doesn't end in .grlx

	path = strings.ReplaceAll(path, ".", string(filepath.Separator))
	// check if path is a directory and contains init.grlx
	initFile := filepath.Join(path, "init."+config.GrlxExt)
	if ok, err := store.Exists(ctx, initFile); err != nil {
		return "", err
	} else if ok {
		return initFile, nil
	}

	// check if path is a valid .grlx file
	extPath := path + "." + config.GrlxExt
	ok, err := store.Exists(ctx, extPath)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", ErrNoRecipe
	}
	return extPath, nil
}
