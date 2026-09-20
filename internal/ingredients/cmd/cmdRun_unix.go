//go:build !windows

package cmd

import (
	"errors"
	"fmt"
	"math"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"
)

// applyRunAs configures cmd to run as the named user. It is a no-op when
// runas is empty. This preserves the behavior that was previously inlined
// in cmdRun.go's "runas != "" && runtime.GOOS != "windows"" check.
func applyRunAs(cmd *exec.Cmd, runas string) error {
	if runas == "" {
		return nil
	}
	u, lookupErr := user.Lookup(runas)
	if lookupErr != nil {
		return errors.Join(lookupErr, fmt.Errorf("invalid user %s; user must exist", runas))
	}
	uid64, strNameErr := strconv.Atoi(u.Uid)
	if strNameErr != nil {
		return errors.Join(strNameErr, fmt.Errorf("invalid user %s; user must exist", runas))
	}
	if uid64 > math.MaxInt32 {
		return fmt.Errorf("UID %d is invalid", uid64)
	}
	uid := uint32(uid64)
	cmd.SysProcAttr = &syscall.SysProcAttr{}
	cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uid}
	return nil
}
