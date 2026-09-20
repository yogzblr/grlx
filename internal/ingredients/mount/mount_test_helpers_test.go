//go:build linux

package mount

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// withTempTables points fstabPath/procMountsPath at temp files seeded with
// the given contents, restoring the originals afterward.
func withTempTables(t *testing.T, fstabContents, mountsContents string) {
	t.Helper()
	dir := t.TempDir()

	fstab := filepath.Join(dir, "fstab")
	if err := os.WriteFile(fstab, []byte(fstabContents), 0o644); err != nil {
		t.Fatalf("failed to seed fstab: %v", err)
	}
	mounts := filepath.Join(dir, "mounts")
	if err := os.WriteFile(mounts, []byte(mountsContents), 0o644); err != nil {
		t.Fatalf("failed to seed mounts: %v", err)
	}

	origFstab, origMounts := fstabPath, procMountsPath
	fstabPath, procMountsPath = fstab, mounts
	t.Cleanup(func() {
		fstabPath, procMountsPath = origFstab, origMounts
	})
}

// mockMountCall records a single invocation of the mocked mountFunc.
type mockMountCall struct {
	source, target, fstype string
	flags                  uintptr
	data                   string
}

func withMockMount(t *testing.T, err error) *[]mockMountCall {
	t.Helper()
	var calls []mockMountCall
	orig := mountFunc
	mountFunc = func(source, target, fstype string, flags uintptr, data string) error {
		calls = append(calls, mockMountCall{source, target, fstype, flags, data})
		return err
	}
	t.Cleanup(func() { mountFunc = orig })
	return &calls
}

func withMockUnmount(t *testing.T, err error) *[]string {
	t.Helper()
	var calls []string
	orig := unmountFunc
	unmountFunc = func(target string, flags int) error {
		calls = append(calls, target)
		return err
	}
	t.Cleanup(func() { unmountFunc = orig })
	return &calls
}

func withMockMkdirAll(t *testing.T) *[]string {
	t.Helper()
	var calls []string
	orig := mkdirAll
	mkdirAll = func(path string, perm os.FileMode) error {
		calls = append(calls, path)
		return nil
	}
	t.Cleanup(func() { mkdirAll = orig })
	return &calls
}

func withMockExecSuccess(t *testing.T) *[][]string {
	t.Helper()
	var calls [][]string
	orig := execCommandContext
	execCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		calls = append(calls, append([]string{name}, args...))
		return exec.CommandContext(ctx, "true")
	}
	t.Cleanup(func() { execCommandContext = orig })
	return &calls
}
