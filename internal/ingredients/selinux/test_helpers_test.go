//go:build linux

package selinux

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// withSelinuxfs points selinuxfsRoot at a temp directory seeded with the
// given boolean files (name -> "active pending" contents), for exercising
// the real filesystem-backed readBoolean/setBoolean primitives directly.
// It is deliberately not used to test boolean.go's higher-level Apply/Test
// logic: see withMockBoolean for why.
func withSelinuxfs(t *testing.T, booleans map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "booleans"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, contents := range booleans {
		if err := os.WriteFile(filepath.Join(dir, "booleans", name), []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "commit_pending_bools"), []byte("0"), 0o644); err != nil {
		t.Fatal(err)
	}
	orig := selinuxfsRoot
	selinuxfsRoot = dir
	t.Cleanup(func() { selinuxfsRoot = orig })
	return dir
}

type mockSetBooleanCall struct {
	name  string
	value bool
}

// withMockBoolean installs an in-memory fake for readBoolean/setBoolean,
// keyed by boolean name. On a real kernel, writing to a boolean file and
// reading it back are not symmetric operations on the same bytes (write
// sets a pending bit; read returns a kernel-synthesized "active pending"
// pair) -- a flat test file can't round-trip that, so boolean.go's
// Apply/Test logic is tested against this fake instead. afterSet lets a
// test simulate a kernel that accepts the write without actually applying
// it (nil means apply exactly as requested).
func withMockBoolean(t *testing.T, initial map[string]bool, afterSet func(name string, requested bool) bool) *[]mockSetBooleanCall {
	t.Helper()
	state := map[string]bool{}
	for k, v := range initial {
		state[k] = v
	}
	var calls []mockSetBooleanCall

	origRead := readBoolean
	origSet := setBoolean
	readBoolean = func(name string) (bool, bool, error) {
		v := state[name]
		return v, v, nil
	}
	setBoolean = func(name string, value bool) error {
		calls = append(calls, mockSetBooleanCall{name, value})
		if afterSet != nil {
			state[name] = afterSet(name, value)
		} else {
			state[name] = value
		}
		return nil
	}
	t.Cleanup(func() {
		readBoolean = origRead
		setBoolean = origSet
	})
	return &calls
}

func withMockEnabled(t *testing.T, enabled bool) {
	t.Helper()
	orig := seGetEnabled
	seGetEnabled = func() bool { return enabled }
	t.Cleanup(func() { seGetEnabled = orig })
}

// withMockMode installs a fake current mode and, on SetEnforceMode, applies
// afterSet (which may differ from the requested mode, to simulate a kernel
// that silently rejects the transition).
func withMockMode(t *testing.T, current int, setErr error, afterSet func(requested int) int) *[]int {
	t.Helper()
	var setCalls []int
	mode := current
	origEnforce := seEnforceMode
	origSet := seSetEnforceMode
	seEnforceMode = func() int { return mode }
	seSetEnforceMode = func(m int) error {
		setCalls = append(setCalls, m)
		if setErr != nil {
			return setErr
		}
		if afterSet != nil {
			mode = afterSet(m)
		} else {
			mode = m
		}
		return nil
	}
	t.Cleanup(func() {
		seEnforceMode = origEnforce
		seSetEnforceMode = origSet
	})
	return &setCalls
}

type mockChconCall struct {
	path    string
	label   string
	recurse bool
}

// withMockFileLabel installs a fake current-label store keyed by path, and
// a Chcon fake that updates it to afterChcon(requested) (which may differ
// from the requested label, to simulate a relabel the kernel didn't apply).
func withMockFileLabel(t *testing.T, labels map[string]string, chconErr error, afterChcon func(requested string) string) *[]mockChconCall {
	t.Helper()
	var calls []mockChconCall
	origLabel := seFileLabel
	origChcon := seChcon
	seFileLabel = func(fpath string) (string, error) {
		return labels[fpath], nil
	}
	seChcon = func(fpath, label string, recurse bool) error {
		calls = append(calls, mockChconCall{fpath, label, recurse})
		if chconErr != nil {
			return chconErr
		}
		if afterChcon != nil {
			labels[fpath] = afterChcon(label)
		} else {
			labels[fpath] = label
		}
		return nil
	}
	t.Cleanup(func() {
		seFileLabel = origLabel
		seChcon = origChcon
	})
	return &calls
}

func withMockLookPath(t *testing.T, found bool) {
	t.Helper()
	orig := lookPath
	lookPath = func(file string) (string, error) {
		if found {
			return "/usr/sbin/" + file, nil
		}
		return "", exec.ErrNotFound
	}
	t.Cleanup(func() { lookPath = orig })
}

func withMockExec(t *testing.T, err error) *[][]string {
	t.Helper()
	var calls [][]string
	orig := execCommandContext
	execCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		calls = append(calls, append([]string{name}, args...))
		if err != nil {
			return exec.CommandContext(ctx, "false")
		}
		return exec.CommandContext(ctx, "true")
	}
	t.Cleanup(func() { execCommandContext = orig })
	return &calls
}
