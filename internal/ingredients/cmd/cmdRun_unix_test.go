//go:build !windows

package cmd

import (
	"os/exec"
	"os/user"
	"testing"
)

func TestApplyRunAsEmptyIsNoop(t *testing.T) {
	command := exec.Command("echo", "test")
	if err := applyRunAs(command, ""); err != nil {
		t.Fatalf("unexpected error for empty runas: %v", err)
	}
	if command.SysProcAttr != nil {
		t.Fatal("expected SysProcAttr to remain unset for empty runas")
	}
}

func TestApplyRunAsCurrentUser(t *testing.T) {
	u, err := user.Current()
	if err != nil {
		t.Skipf("cannot get current user: %v", err)
	}
	command := exec.Command("echo", "test")
	if err := applyRunAs(command, u.Username); err != nil {
		t.Fatalf("unexpected error setting runas to current user %q: %v", u.Username, err)
	}
	if command.SysProcAttr == nil || command.SysProcAttr.Credential == nil {
		t.Fatal("expected SysProcAttr.Credential to be set")
	}
}

func TestApplyRunAsNonexistentUser(t *testing.T) {
	command := exec.Command("echo", "test")
	if err := applyRunAs(command, "nonexistent_user_xyz_99999"); err == nil {
		t.Error("expected error for nonexistent user")
	}
}
