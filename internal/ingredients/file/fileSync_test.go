package file

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestSyncBasicCopiesAndSkipsUnchanged(t *testing.T) {
	dir := t.TempDir()
	srcDir := filepath.Join(dir, "src")
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTempFile(t, srcDir, "a.txt", "aaa")
	dstDir := filepath.Join(dir, "dst")

	f := File{params: map[string]interface{}{"name": dstDir, "source": srcDir, "mkdir": true}}
	res, err := f.sync(context.Background(), false)
	if err != nil || !res.Succeeded || !res.Changed {
		t.Fatalf("expected success+changed, got res=%+v err=%v", res, err)
	}
	if _, err := os.Stat(filepath.Join(dstDir, "a.txt")); err != nil {
		t.Fatalf("expected a.txt synced: %v", err)
	}

	res, err = f.sync(context.Background(), false)
	if err != nil || !res.Succeeded || res.Changed {
		t.Fatalf("expected no-op on second sync, got res=%+v err=%v", res, err)
	}
}

func TestSyncDeleteOrphans(t *testing.T) {
	dir := t.TempDir()
	srcDir := filepath.Join(dir, "src")
	dstDir := filepath.Join(dir, "dst")
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTempFile(t, srcDir, "keep.txt", "keep")
	writeTempFile(t, dstDir, "orphan.txt", "should be removed")

	f := File{params: map[string]interface{}{"name": dstDir, "source": srcDir, "delete": true}}
	res, err := f.sync(context.Background(), false)
	if err != nil || !res.Succeeded || !res.Changed {
		t.Fatalf("expected success+changed, got res=%+v err=%v", res, err)
	}
	if _, err := os.Stat(filepath.Join(dstDir, "orphan.txt")); !os.IsNotExist(err) {
		t.Errorf("expected orphan.txt removed, stat err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(dstDir, "keep.txt")); err != nil {
		t.Errorf("expected keep.txt to remain: %v", err)
	}
}

func TestSyncWithoutDeleteKeepsOrphans(t *testing.T) {
	dir := t.TempDir()
	srcDir := filepath.Join(dir, "src")
	dstDir := filepath.Join(dir, "dst")
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTempFile(t, dstDir, "orphan.txt", "stays")

	f := File{params: map[string]interface{}{"name": dstDir, "source": srcDir}}
	res, err := f.sync(context.Background(), false)
	if err != nil || !res.Succeeded {
		t.Fatalf("expected success, got res=%+v err=%v", res, err)
	}
	if _, err := os.Stat(filepath.Join(dstDir, "orphan.txt")); err != nil {
		t.Errorf("expected orphan.txt to remain without delete: %v", err)
	}
}

func TestSyncExclude(t *testing.T) {
	dir := t.TempDir()
	srcDir := filepath.Join(dir, "src")
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTempFile(t, srcDir, "keep.txt", "keep")
	writeTempFile(t, srcDir, "skip.log", "skip")
	dstDir := filepath.Join(dir, "dst")

	f := File{params: map[string]interface{}{
		"name": dstDir, "source": srcDir, "mkdir": true,
		"exclude": []interface{}{"*.log"},
	}}
	if _, err := f.sync(context.Background(), false); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dstDir, "keep.txt")); err != nil {
		t.Errorf("expected keep.txt synced: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dstDir, "skip.log")); !os.IsNotExist(err) {
		t.Errorf("expected skip.log excluded, stat err=%v", err)
	}
}

func TestSyncMissingDestWithoutMkdirFails(t *testing.T) {
	dir := t.TempDir()
	srcDir := filepath.Join(dir, "src")
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	f := File{params: map[string]interface{}{"name": filepath.Join(dir, "dst"), "source": srcDir}}
	if _, err := f.sync(context.Background(), false); err == nil {
		t.Fatal("expected error without mkdir")
	}
}

func TestSyncTestModeDoesNotMutate(t *testing.T) {
	dir := t.TempDir()
	srcDir := filepath.Join(dir, "src")
	dstDir := filepath.Join(dir, "dst")
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTempFile(t, srcDir, "new.txt", "new")
	writeTempFile(t, dstDir, "orphan.txt", "orphan")

	f := File{params: map[string]interface{}{"name": dstDir, "source": srcDir, "delete": true}}
	res, err := f.sync(context.Background(), true)
	if err != nil || !res.Succeeded || !res.Changed {
		t.Fatalf("expected predicted changes, got res=%+v err=%v", res, err)
	}
	if _, err := os.Stat(filepath.Join(dstDir, "new.txt")); !os.IsNotExist(err) {
		t.Errorf("test mode must not create new.txt")
	}
	if _, err := os.Stat(filepath.Join(dstDir, "orphan.txt")); err != nil {
		t.Errorf("test mode must not remove orphan.txt: %v", err)
	}
}

func TestSyncMissingSourceOrName(t *testing.T) {
	if _, err := (File{params: map[string]interface{}{"source": "/tmp/x"}}).sync(context.Background(), false); err == nil {
		t.Fatal("expected error for missing name")
	}
	if _, err := (File{params: map[string]interface{}{"name": "/tmp/x"}}).sync(context.Background(), false); err == nil {
		t.Fatal("expected error for missing source")
	}
}
