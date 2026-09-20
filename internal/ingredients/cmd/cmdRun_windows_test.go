//go:build windows

package cmd

import (
	"os/exec"
	"testing"
)

// NOTE: this file is built only under GOOS=windows. It has been verified to
// compile via `GOOS=windows GOARCH=amd64 go build/vet`, but has not been
// executed on an actual Windows toolchain/runner - please verify on real
// Windows CI before relying on it.

func TestApplyRunAsEmptyIsNoop(t *testing.T) {
	command := exec.Command("cmd", "/C", "echo", "test")
	if err := applyRunAs(command, ""); err != nil {
		t.Fatalf("unexpected error for empty runas: %v", err)
	}
}

func TestApplyRunAsRejectsNonEmptyRunAs(t *testing.T) {
	command := exec.Command("cmd", "/C", "echo", "test")
	if err := applyRunAs(command, "someuser"); err == nil {
		t.Error("expected non-nil error when runas is set on Windows")
	}
}
