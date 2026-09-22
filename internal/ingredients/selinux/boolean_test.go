//go:build linux

package selinux

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestBooleanApplyAlreadyOnNoChange(t *testing.T) {
	withMockEnabled(t, true)
	calls := withMockBoolean(t, map[string]bool{"httpd_can_network_connect": true}, nil)

	s := SELinux{id: "t", method: "boolean_on", params: map[string]interface{}{"name": "httpd_can_network_connect"}}
	result, err := s.Apply(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Succeeded || result.Failed || result.Changed {
		t.Fatalf("unexpected result: %+v", result)
	}
	if len(*calls) != 0 {
		t.Fatalf("expected no setsebool calls, got %v", *calls)
	}
}

func TestBooleanApplyTurnsOnAndCommits(t *testing.T) {
	withMockEnabled(t, true)
	calls := withMockBoolean(t, map[string]bool{"httpd_can_network_connect": false}, nil)

	s := SELinux{id: "t", method: "boolean_on", params: map[string]interface{}{"name": "httpd_can_network_connect"}}
	result, err := s.Apply(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Succeeded || result.Failed || !result.Changed {
		t.Fatalf("unexpected result: %+v", result)
	}
	if len(*calls) != 1 || (*calls)[0] != (mockSetBooleanCall{"httpd_can_network_connect", true}) {
		t.Fatalf("expected one setsebool(on) call, got %v", *calls)
	}
}

func TestBooleanApplyTestModeDoesNotWrite(t *testing.T) {
	withMockEnabled(t, true)
	calls := withMockBoolean(t, map[string]bool{"httpd_can_network_connect": false}, nil)

	s := SELinux{id: "t", method: "boolean_on", params: map[string]interface{}{"name": "httpd_can_network_connect"}}
	result, err := s.Test(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Succeeded || result.Failed || !result.Changed {
		t.Fatalf("unexpected result: %+v", result)
	}
	if len(*calls) != 0 {
		t.Fatalf("test mode must not call setsebool, got %v", *calls)
	}
}

func TestBooleanApplyMissingNameError(t *testing.T) {
	s := SELinux{id: "t", method: "boolean_on", params: map[string]interface{}{}}
	result, err := s.Apply(context.Background())
	if err == nil {
		t.Fatal("expected error for missing name")
	}
	if !result.Failed {
		t.Fatalf("expected Failed=true, got %+v", result)
	}
}

func TestBooleanApplyDisabledHostFailsLoudly(t *testing.T) {
	withMockEnabled(t, false)

	s := SELinux{id: "t", method: "boolean_on", params: map[string]interface{}{"name": "foo"}}
	result, err := s.Apply(context.Background())
	if err == nil {
		t.Fatal("expected an error when SELinux is disabled")
	}
	if !result.Failed {
		t.Fatalf("expected Failed=true, got %+v", result)
	}
}

func TestBooleanApplyPersistWithoutSemanageFailsLoudly(t *testing.T) {
	withMockEnabled(t, true)
	withMockBoolean(t, map[string]bool{"httpd_can_network_connect": true}, nil)
	withMockLookPath(t, false)

	s := SELinux{id: "t", method: "boolean_on", params: map[string]interface{}{
		"name": "httpd_can_network_connect", "persist": true,
	}}
	result, err := s.Apply(context.Background())
	if err == nil {
		t.Fatal("expected an error when semanage is unavailable and persist was requested")
	}
	if !result.Failed {
		t.Fatalf("expected Failed=true, got %+v", result)
	}
}

func TestBooleanApplyPersistShellsToSemanage(t *testing.T) {
	withMockEnabled(t, true)
	withMockBoolean(t, map[string]bool{"httpd_can_network_connect": false}, nil)
	withMockLookPath(t, true)
	calls := withMockExec(t, nil)

	s := SELinux{id: "t", method: "boolean_on", params: map[string]interface{}{
		"name": "httpd_can_network_connect", "persist": true,
	}}
	result, err := s.Apply(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Succeeded || result.Failed || !result.Changed {
		t.Fatalf("unexpected result: %+v", result)
	}
	if len(*calls) != 1 {
		t.Fatalf("expected one semanage invocation, got %v", *calls)
	}
	got := (*calls)[0]
	want := []string{"semanage", "boolean", "-m", "--on", "httpd_can_network_connect"}
	if len(got) != len(want) {
		t.Fatalf("unexpected semanage args: %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unexpected semanage args: %v", got)
		}
	}
}

// TestBooleanApplyRejectsSilentDegrade mirrors the mode-change compliance
// concern: a setsebool write that the kernel doesn't actually apply must
// not be reported as success.
func TestBooleanApplyRejectsSilentDegrade(t *testing.T) {
	withMockEnabled(t, true)
	withMockBoolean(t, map[string]bool{"httpd_can_network_connect": false},
		func(name string, requested bool) bool {
			return false // kernel ignores the write
		})

	s := SELinux{id: "t", method: "boolean_on", params: map[string]interface{}{"name": "httpd_can_network_connect"}}
	result, err := s.Apply(context.Background())
	if err == nil {
		t.Fatal("expected an error when the verified boolean doesn't match the requested value")
	}
	if !result.Failed || result.Succeeded {
		t.Fatalf("expected Failed=true, Succeeded=false; got %+v", result)
	}
}

// The tests below exercise the real filesystem-backed readBoolean/
// setBoolean primitives (as opposed to boolean.go's Apply/Test logic,
// which is tested above against withMockBoolean).

func TestReadBooleanParsesActiveAndPending(t *testing.T) {
	withSelinuxfs(t, map[string]string{"httpd_can_network_connect": "0 1"})

	active, pending, err := readBoolean("httpd_can_network_connect")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if active {
		t.Fatal("expected active=false")
	}
	if !pending {
		t.Fatal("expected pending=true")
	}
}

func TestReadBooleanRejectsMalformedContent(t *testing.T) {
	withSelinuxfs(t, map[string]string{"httpd_can_network_connect": "not-a-boolean"})

	if _, _, err := readBoolean("httpd_can_network_connect"); err == nil {
		t.Fatal("expected an error for malformed boolean content")
	}
}

func TestSetBooleanWritesPendingAndCommits(t *testing.T) {
	root := withSelinuxfs(t, map[string]string{"httpd_can_network_connect": "0 0"})

	if err := setBoolean("httpd_can_network_connect", true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	pending, err := os.ReadFile(filepath.Join(root, "booleans", "httpd_can_network_connect"))
	if err != nil {
		t.Fatalf("unexpected error reading boolean file: %v", err)
	}
	if string(pending) != "1" {
		t.Fatalf("expected pending write of %q, got %q", "1", pending)
	}

	commit, err := os.ReadFile(filepath.Join(root, "commit_pending_bools"))
	if err != nil {
		t.Fatalf("unexpected error reading commit file: %v", err)
	}
	if string(commit) != "1" {
		t.Fatalf("expected commit_pending_bools to be written, got %q", commit)
	}
}
