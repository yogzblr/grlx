package file

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestCopySingleFilePush(t *testing.T) {
	dir := t.TempDir()
	src := writeTempFile(t, dir, "src.txt", "hello")
	dst := filepath.Join(dir, "sub", "dst.txt")

	f := File{params: map[string]interface{}{"name": dst, "source": src, "mkdir": true}}
	res, err := f.copy(context.Background(), false)
	if err != nil || !res.Succeeded || !res.Changed {
		t.Fatalf("expected success+changed, got res=%+v err=%v", res, err)
	}
	got, err := os.ReadFile(dst)
	if err != nil || string(got) != "hello" {
		t.Fatalf("dst content = %q, err=%v", got, err)
	}

	// re-running should be a no-op (unchanged)
	res, err = f.copy(context.Background(), false)
	if err != nil || !res.Succeeded || res.Changed {
		t.Fatalf("expected no-op on second run, got res=%+v err=%v", res, err)
	}
}

func TestCopyMissingParentWithoutMkdirFails(t *testing.T) {
	dir := t.TempDir()
	src := writeTempFile(t, dir, "src.txt", "hello")
	dst := filepath.Join(dir, "sub", "dst.txt")

	f := File{params: map[string]interface{}{"name": dst, "source": src}}
	if _, err := f.copy(context.Background(), false); err == nil {
		t.Fatal("expected error without mkdir")
	}
}

func TestCopyPullDirection(t *testing.T) {
	dir := t.TempDir()
	localSrc := writeTempFile(t, dir, "local.txt", "local-content")
	backupDst := filepath.Join(dir, "backup.txt")

	// pull: name is the local source, source is the destination
	f := File{params: map[string]interface{}{"name": localSrc, "source": backupDst, "direction": "pull"}}
	res, err := f.copy(context.Background(), false)
	if err != nil || !res.Succeeded || !res.Changed {
		t.Fatalf("expected success+changed, got res=%+v err=%v", res, err)
	}
	got, err := os.ReadFile(backupDst)
	if err != nil || string(got) != "local-content" {
		t.Fatalf("backup content = %q, err=%v", got, err)
	}
}

func TestCopyInvalidDirection(t *testing.T) {
	dir := t.TempDir()
	src := writeTempFile(t, dir, "src.txt", "hello")
	f := File{params: map[string]interface{}{"name": filepath.Join(dir, "dst.txt"), "source": src, "direction": "sideways"}}
	if _, err := f.copy(context.Background(), false); err == nil {
		t.Fatal("expected error for invalid direction")
	}
}

func TestCopyDirectoryWithGlobAndExclude(t *testing.T) {
	dir := t.TempDir()
	srcDir := filepath.Join(dir, "src")
	if err := os.MkdirAll(filepath.Join(srcDir, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeTempFile(t, srcDir, "keep.conf", "keep")
	writeTempFile(t, srcDir, "skip.conf", "skip-me")
	if err := os.WriteFile(filepath.Join(srcDir, "nested", "deep.conf"), []byte("deep"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeTempFile(t, srcDir, "ignore.txt", "not a conf")

	dstDir := filepath.Join(dir, "dst")
	f := File{params: map[string]interface{}{
		"name": dstDir, "source": srcDir,
		"glob":    "*.conf",
		"exclude": []interface{}{"skip.conf"},
		"mkdir":   true,
	}}
	res, err := f.copy(context.Background(), false)
	if err != nil || !res.Succeeded || !res.Changed {
		t.Fatalf("expected success+changed, got res=%+v err=%v", res, err)
	}

	if _, err := os.Stat(filepath.Join(dstDir, "keep.conf")); err != nil {
		t.Errorf("expected keep.conf to be copied: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dstDir, "skip.conf")); !os.IsNotExist(err) {
		t.Errorf("expected skip.conf to be excluded, stat err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(dstDir, "ignore.txt")); !os.IsNotExist(err) {
		t.Errorf("expected ignore.txt to not match glob, stat err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(dstDir, "nested", "deep.conf")); err != nil {
		t.Errorf("expected nested/deep.conf to be copied: %v", err)
	}
}

func TestCopyChmodX(t *testing.T) {
	dir := t.TempDir()
	src := writeTempFile(t, dir, "script.sh", "#!/bin/sh\necho hi")
	dst := filepath.Join(dir, "script-copy.sh")

	f := File{params: map[string]interface{}{"name": dst, "source": src, "chmod_x": true}}
	if _, err := f.copy(context.Background(), false); err != nil {
		t.Fatalf("copy: %v", err)
	}
	info, err := os.Stat(dst)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Errorf("expected executable bits set, got mode %v", info.Mode())
	}
}

func TestCopyTestModeDoesNotWrite(t *testing.T) {
	dir := t.TempDir()
	src := writeTempFile(t, dir, "src.txt", "hello")
	dst := filepath.Join(dir, "dst.txt")

	f := File{params: map[string]interface{}{"name": dst, "source": src}}
	res, err := f.copy(context.Background(), true)
	if err != nil || !res.Succeeded || !res.Changed {
		t.Fatalf("expected predicted change, got res=%+v err=%v", res, err)
	}
	if _, statErr := os.Stat(dst); !os.IsNotExist(statErr) {
		t.Errorf("test mode must not create destination file")
	}
}

func TestCopyMissingSource(t *testing.T) {
	if _, err := (File{params: map[string]interface{}{"name": "/tmp/x"}}).copy(context.Background(), false); err == nil {
		t.Fatal("expected error for missing source")
	}
}
