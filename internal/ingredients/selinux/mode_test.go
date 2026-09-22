//go:build linux

package selinux

import (
	"context"
	"errors"
	"testing"

	goselinux "github.com/opencontainers/selinux/go-selinux"
)

var errPermissionDenied = errors.New("permission denied")

func TestModeApplyDisabledHostFailsLoudly(t *testing.T) {
	withMockEnabled(t, false)

	s := SELinux{id: "t", method: "enforcing"}
	result, err := s.Apply(context.Background())
	if err == nil {
		t.Fatal("expected an error when SELinux is disabled")
	}
	if !result.Failed || result.Succeeded {
		t.Fatalf("expected Failed=true, Succeeded=false; got %+v", result)
	}
}

func TestModeApplyAlreadyEnforcingNoChange(t *testing.T) {
	withMockEnabled(t, true)
	withMockMode(t, goselinux.Enforcing, nil, nil)

	s := SELinux{id: "t", method: "enforcing"}
	result, err := s.Apply(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Succeeded || result.Failed || result.Changed {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestModeApplySwitchesAndVerifies(t *testing.T) {
	withMockEnabled(t, true)
	calls := withMockMode(t, goselinux.Permissive, nil, nil)

	s := SELinux{id: "t", method: "enforcing"}
	result, err := s.Apply(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Succeeded || result.Failed || !result.Changed {
		t.Fatalf("unexpected result: %+v", result)
	}
	if len(*calls) != 1 || (*calls)[0] != goselinux.Enforcing {
		t.Fatalf("expected a single SetEnforceMode(Enforcing) call, got %v", *calls)
	}
}

func TestModeApplyTestModeDoesNotCallSet(t *testing.T) {
	withMockEnabled(t, true)
	calls := withMockMode(t, goselinux.Permissive, nil, nil)

	s := SELinux{id: "t", method: "enforcing"}
	result, err := s.Test(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Succeeded || result.Failed || !result.Changed {
		t.Fatalf("unexpected result: %+v", result)
	}
	if len(*calls) != 0 {
		t.Fatalf("expected no SetEnforceMode calls in test mode, got %v", *calls)
	}
}

func TestModeApplySetenforceErrors(t *testing.T) {
	withMockEnabled(t, true)
	withMockMode(t, goselinux.Permissive, errPermissionDenied, nil)

	s := SELinux{id: "t", method: "enforcing"}
	result, err := s.Apply(context.Background())
	if err == nil {
		t.Fatal("expected error from failing setenforce")
	}
	if !result.Failed {
		t.Fatalf("expected Failed=true, got %+v", result)
	}
}

// TestModeApplyRejectsSilentDegrade is the compliance-relevant case flagged
// by the roadmap: the kernel accepts the write call without erroring but
// the mode doesn't actually change (e.g. a policy that failed to load).
// The ingredient must not report success on that -- silently staying
// permissive is exactly the failure mode this ingredient exists to avoid.
func TestModeApplyRejectsSilentDegrade(t *testing.T) {
	withMockEnabled(t, true)
	withMockMode(t, goselinux.Permissive, nil, func(requested int) int {
		return goselinux.Permissive // kernel ignores the write
	})

	s := SELinux{id: "t", method: "enforcing"}
	result, err := s.Apply(context.Background())
	if err == nil {
		t.Fatal("expected an error when the verified mode doesn't match the requested mode")
	}
	if !result.Failed || result.Succeeded {
		t.Fatalf("expected Failed=true, Succeeded=false; got %+v", result)
	}
}

func TestModeNameUnknown(t *testing.T) {
	if got := modeName(99); got != "unknown(99)" {
		t.Fatalf("unexpected modeName output: %s", got)
	}
}
