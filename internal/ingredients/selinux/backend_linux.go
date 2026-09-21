//go:build linux

package selinux

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	goselinux "github.com/opencontainers/selinux/go-selinux"
)

// selinuxfsRoot is the mountpoint of the selinuxfs pseudo-filesystem, which
// exposes booleans directly to the kernel. opencontainers/selinux doesn't
// export the mountpoint lookup it uses internally for EnforceMode/
// GetEnabled, but /sys/fs/selinux is the path every mainstream distribution
// mounts it at, and the one the library itself tries first. Tests point
// this at a fake directory tree instead of requiring a real
// SELinux-enabled kernel.
var selinuxfsRoot = "/sys/fs/selinux"

func booleansDir() string            { return filepath.Join(selinuxfsRoot, "booleans") }
func commitPendingBoolsPath() string { return filepath.Join(selinuxfsRoot, "commit_pending_bools") }

// Wrapped as package vars so tests can substitute fakes without needing a
// real SELinux-enabled kernel or root privileges.
var (
	seGetEnabled     = goselinux.GetEnabled
	seEnforceMode    = goselinux.EnforceMode
	seSetEnforceMode = goselinux.SetEnforceMode
	seFileLabel      = goselinux.FileLabel
	seChcon          = goselinux.Chcon

	execCommandContext = exec.CommandContext
	lookPath           = exec.LookPath
)

// readBoolean returns a boolean's current active value and its pending
// (uncommitted) value, exactly as selinuxfs reports them. Wrapped as a var,
// alongside setBoolean, so boolean.go's Apply/Test logic can be tested
// against an in-memory fake instead of a real selinuxfs mount: on a real
// kernel, writing to the boolean file and reading it back are not
// symmetric (write sets a pending bit; read returns a kernel-synthesized
// "active pending" pair), which a flat test file can't round-trip.
var readBoolean = func(name string) (active, pending bool, err error) {
	data, err := os.ReadFile(filepath.Join(booleansDir(), name))
	if err != nil {
		return false, false, err
	}
	fields := strings.Fields(string(data))
	if len(fields) != 2 {
		return false, false, fmt.Errorf("unexpected boolean format for %s: %q", name, data)
	}
	return fields[0] == "1", fields[1] == "1", nil
}

// setBoolean sets name's pending value and immediately commits it -- what
// `setsebool <name> <value>` (without -P) does under the hood. Wrapped as a
// var so tests can simulate a kernel that accepts the write without
// actually applying it.
var setBoolean = func(name string, value bool) error {
	v := []byte("0")
	if value {
		v = []byte("1")
	}
	if err := os.WriteFile(filepath.Join(booleansDir(), name), v, 0o644); err != nil {
		return err
	}
	return os.WriteFile(commitPendingBoolsPath(), []byte("1"), 0o644)
}

// persistBoolean shells out to semanage to make a boolean change survive a
// reboot or relabel. There is no pure-Go path to SELinux's persisted policy
// store (it lives in a binary database normally owned by libsemanage), so
// this is a deliberate cmd fallback -- the same pattern the mount
// ingredient uses for network filesystems the raw mount(2) syscall can't
// handle. Persist is opt-in per step, so a missing semanage binary is a
// hard failure here rather than a silent skip.
func persistBoolean(ctx context.Context, name string, value bool) error {
	if _, err := lookPath("semanage"); err != nil {
		return fmt.Errorf("persist requested for boolean %s but semanage is not installed: %w", name, err)
	}
	flag := "--off"
	if value {
		flag = "--on"
	}
	cmd := execCommandContext(ctx, "semanage", "boolean", "-m", flag, name)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("semanage boolean -m %s %s: %w: %s", flag, name, err, strings.TrimSpace(string(out)))
	}
	return nil
}
