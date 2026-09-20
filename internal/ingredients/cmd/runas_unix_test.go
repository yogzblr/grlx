//go:build !windows

package cmd

import (
	"os/exec"
	"os/user"
	"strconv"
	"testing"
)

func TestSetRunAsCurrentUser(t *testing.T) {
	u, err := user.Current()
	if err != nil {
		t.Skipf("cannot get current user: %v", err)
	}
	command := exec.Command("echo", "test")
	err = setRunAs(command, u.Username)
	if err != nil {
		t.Fatalf("unexpected error setting runas to current user %q: %v", u.Username, err)
	}
	if command.SysProcAttr == nil {
		t.Fatal("expected SysProcAttr to be set")
	}
	if command.SysProcAttr.Credential == nil {
		t.Fatal("expected Credential to be set")
	}
	wantUID, err := strconv.Atoi(u.Uid)
	if err != nil {
		t.Fatalf("cannot parse current user's uid %q: %v", u.Uid, err)
	}
	wantGID, err := strconv.Atoi(u.Gid)
	if err != nil {
		t.Fatalf("cannot parse current user's gid %q: %v", u.Gid, err)
	}
	if got := command.SysProcAttr.Credential.Uid; got != uint32(wantUID) {
		t.Errorf("Credential.Uid = %d, want %d", got, wantUID)
	}
	if got := command.SysProcAttr.Credential.Gid; got != uint32(wantGID) {
		t.Errorf("Credential.Gid = %d, want %d", got, wantGID)
	}
}

func TestSetRunAsNonexistentUser(t *testing.T) {
	command := exec.Command("echo", "test")
	err := setRunAs(command, "nonexistent_user_xyz_99999")
	if err == nil {
		t.Error("expected error for nonexistent user")
	}
}

func TestSetRunAsEmptyIsNoop(t *testing.T) {
	command := exec.Command("echo", "test")
	if err := setRunAs(command, ""); err != nil {
		t.Fatalf("unexpected error for empty runas: %v", err)
	}
	if command.SysProcAttr != nil {
		t.Fatal("expected SysProcAttr to remain unset for empty runas")
	}
}
