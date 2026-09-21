//go:build windows

package main

import (
	_ "github.com/gogrlx/grlx/v2/internal/ingredients/registry"
	_ "github.com/gogrlx/grlx/v2/internal/ingredients/service/windows"
	_ "github.com/gogrlx/grlx/v2/internal/ingredients/winappx"
	_ "github.com/gogrlx/grlx/v2/internal/ingredients/winauditpol"
	_ "github.com/gogrlx/grlx/v2/internal/ingredients/wincertutil"
	_ "github.com/gogrlx/grlx/v2/internal/ingredients/windnsclient"
	_ "github.com/gogrlx/grlx/v2/internal/ingredients/windsc"
	_ "github.com/gogrlx/grlx/v2/internal/ingredients/winfirewall"
	_ "github.com/gogrlx/grlx/v2/internal/ingredients/winiis"
	_ "github.com/gogrlx/grlx/v2/internal/ingredients/winpki"
	_ "github.com/gogrlx/grlx/v2/internal/ingredients/winpowercfg"
	_ "github.com/gogrlx/grlx/v2/internal/ingredients/winpsget"
	_ "github.com/gogrlx/grlx/v2/internal/ingredients/winservermanager"
	_ "github.com/gogrlx/grlx/v2/internal/ingredients/winshortcut"
	_ "github.com/gogrlx/grlx/v2/internal/ingredients/winsmtpserver"
	_ "github.com/gogrlx/grlx/v2/internal/ingredients/winsnmp"
)
