//go:build windows

package cmd

import (
	"fmt"
	"os/exec"
)

// applyRunAs is not supported on Windows. It is a no-op when runas is
// empty, and returns an explicit error otherwise instead of silently
// ignoring the requested user.
func applyRunAs(cmd *exec.Cmd, runas string) error {
	if runas == "" {
		return nil
	}
	return fmt.Errorf("runas is not supported on Windows")
}
