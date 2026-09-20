//go:build windows

package cmd

import (
	"fmt"
	"os/exec"
)

// setRunAs is not supported on Windows. It is a no-op when runAs is
// empty, and returns an explicit error otherwise instead of silently
// ignoring the requested user.
func setRunAs(command *exec.Cmd, runAs string) error {
	if runAs == "" {
		return nil
	}
	return fmt.Errorf("RunAs is not supported on Windows")
}
