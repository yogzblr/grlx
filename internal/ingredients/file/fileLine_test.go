package file

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTempFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	return p
}

func TestLineEnsureAddsMissingLine(t *testing.T) {
	dir := t.TempDir()
	p := writeTempFile(t, dir, "f.txt", "one\ntwo\n")

	f := File{params: map[string]interface{}{"name": p, "mode": "ensure", "content": "three"}}
	res, err := f.line(context.Background(), false)
	if err != nil || !res.Succeeded || !res.Changed {
		t.Fatalf("expected success+changed, got res=%+v err=%v", res, err)
	}
	got, _ := os.ReadFile(p)
	if !strings.Contains(string(got), "three") {
		t.Errorf("expected line added, got:\n%s", got)
	}
}

func TestLineEnsureNoopWhenPresent(t *testing.T) {
	dir := t.TempDir()
	p := writeTempFile(t, dir, "f.txt", "one\ntwo\n")

	f := File{params: map[string]interface{}{"name": p, "mode": "ensure", "content": "two"}}
	res, err := f.line(context.Background(), false)
	if err != nil || !res.Succeeded || res.Changed {
		t.Fatalf("expected success without change, got res=%+v err=%v", res, err)
	}
}

func TestLineReplace(t *testing.T) {
	dir := t.TempDir()
	p := writeTempFile(t, dir, "f.txt", "port=8080\nother=1\n")

	f := File{params: map[string]interface{}{
		"name": p, "mode": "replace", "match": `^port=.*`, "content": "port=9090",
	}}
	res, err := f.line(context.Background(), false)
	if err != nil || !res.Succeeded || !res.Changed {
		t.Fatalf("expected success+changed, got res=%+v err=%v", res, err)
	}
	got, _ := os.ReadFile(p)
	if !strings.Contains(string(got), "port=9090") || strings.Contains(string(got), "port=8080") {
		t.Errorf("unexpected content:\n%s", got)
	}
}

func TestLineDelete(t *testing.T) {
	dir := t.TempDir()
	p := writeTempFile(t, dir, "f.txt", "keep\nremove-me\nkeep2\n")

	f := File{params: map[string]interface{}{"name": p, "mode": "delete", "match": "remove-me"}}
	res, err := f.line(context.Background(), false)
	if err != nil || !res.Succeeded || !res.Changed {
		t.Fatalf("expected success+changed, got res=%+v err=%v", res, err)
	}
	got, _ := os.ReadFile(p)
	if strings.Contains(string(got), "remove-me") {
		t.Errorf("expected line removed, got:\n%s", got)
	}
}

func TestLineInsertAfterMatch(t *testing.T) {
	dir := t.TempDir()
	p := writeTempFile(t, dir, "f.txt", "a\nb\nc\n")

	f := File{params: map[string]interface{}{
		"name": p, "mode": "insert", "match": "^b$", "content": "b2", "location": "after",
	}}
	res, err := f.line(context.Background(), false)
	if err != nil || !res.Succeeded || !res.Changed {
		t.Fatalf("expected success+changed, got res=%+v err=%v", res, err)
	}
	got, _ := os.ReadFile(p)
	want := "a\nb\nb2\nc\n"
	if string(got) != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestLineInsertNoMatchNoLocationAppendsAtEnd(t *testing.T) {
	dir := t.TempDir()
	p := writeTempFile(t, dir, "f.txt", "a\nb\n")

	f := File{params: map[string]interface{}{"name": p, "mode": "insert", "content": "z"}}
	res, err := f.line(context.Background(), false)
	if err != nil || !res.Succeeded || !res.Changed {
		t.Fatalf("expected success+changed, got res=%+v err=%v", res, err)
	}
	got, _ := os.ReadFile(p)
	if string(got) != "a\nb\nz\n" {
		t.Errorf("got %q", got)
	}
}

func TestLineTestModeDoesNotWrite(t *testing.T) {
	dir := t.TempDir()
	p := writeTempFile(t, dir, "f.txt", "one\n")

	f := File{params: map[string]interface{}{"name": p, "mode": "ensure", "content": "two"}}
	res, err := f.line(context.Background(), true)
	if err != nil || !res.Succeeded || !res.Changed {
		t.Fatalf("expected success+changed report, got res=%+v err=%v", res, err)
	}
	got, _ := os.ReadFile(p)
	if strings.Contains(string(got), "two") {
		t.Errorf("test mode must not write, got:\n%s", got)
	}
}

func TestLineMissingModeAndFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "missing.txt")

	if _, err := (File{params: map[string]interface{}{"name": p}}).line(context.Background(), false); err == nil {
		t.Fatal("expected error for missing mode")
	}
	if _, err := (File{params: map[string]interface{}{"name": p, "mode": "ensure", "content": "x"}}).line(context.Background(), false); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLineInvalidModeAndMissingMatch(t *testing.T) {
	dir := t.TempDir()
	p := writeTempFile(t, dir, "f.txt", "a\n")

	if _, err := (File{params: map[string]interface{}{"name": p, "mode": "bogus"}}).line(context.Background(), false); err == nil {
		t.Fatal("expected error for invalid mode")
	}
	if _, err := (File{params: map[string]interface{}{"name": p, "mode": "replace", "content": "x"}}).line(context.Background(), false); err == nil {
		t.Fatal("expected error for replace without match")
	}
}
