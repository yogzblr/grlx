//go:build linux

package main

import (
	_ "github.com/gogrlx/grlx/v2/internal/ingredients/cron"
	_ "github.com/gogrlx/grlx/v2/internal/ingredients/firewall"
	_ "github.com/gogrlx/grlx/v2/internal/ingredients/mount"
	_ "github.com/gogrlx/grlx/v2/internal/ingredients/selinux"
	_ "github.com/gogrlx/grlx/v2/internal/ingredients/service/openrc"
	_ "github.com/gogrlx/grlx/v2/internal/ingredients/service/systemd"
)
