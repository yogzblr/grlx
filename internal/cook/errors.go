package cook

import (
	"errors"
)

var (
	ErrNoRecipe              = errors.New("no recipe")
	ErrInvalidFormat         = errors.New("invalid recipe format")
	ErrDuplicateKey          = errors.New("duplicate key in joined maps")
	ErrRecipePathIsDirectory = errors.New("recipe path resolved to a directory instead of a .grlx file")
	ErrTargetStepNotFound    = errors.New("target step not found in recipe")
	ErrDanglingRequisite     = errors.New("step requires an unknown step")
	ErrInvalidCond           = errors.New("invalid cond")
	ErrInvalidRegister       = errors.New("invalid register")
	ErrInvalidSecrets        = errors.New("invalid secrets")
	ErrInvalidOnExit         = errors.New("invalid on_exit")
)
