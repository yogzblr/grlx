package main

import (
	_ "github.com/gogrlx/grlx/v2/internal/ingredients/cmd"
	_ "github.com/gogrlx/grlx/v2/internal/ingredients/file"
	_ "github.com/gogrlx/grlx/v2/internal/ingredients/file/http"
	_ "github.com/gogrlx/grlx/v2/internal/ingredients/file/local"
	_ "github.com/gogrlx/grlx/v2/internal/ingredients/group"
	_ "github.com/gogrlx/grlx/v2/internal/ingredients/pkg"
	_ "github.com/gogrlx/grlx/v2/internal/ingredients/probe"
	_ "github.com/gogrlx/grlx/v2/internal/ingredients/sdb/awssm"
	_ "github.com/gogrlx/grlx/v2/internal/ingredients/sdb/azurekv"
	_ "github.com/gogrlx/grlx/v2/internal/ingredients/sdb/gcpsm"
	_ "github.com/gogrlx/grlx/v2/internal/ingredients/sdb/openbao"
	_ "github.com/gogrlx/grlx/v2/internal/ingredients/selfupdate"
	_ "github.com/gogrlx/grlx/v2/internal/ingredients/user"
	_ "github.com/gogrlx/grlx/v2/internal/ingredients/wait"
)
