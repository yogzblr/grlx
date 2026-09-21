//go:build linux

package selinux

import (
	"context"
	"testing"
)

func TestContextPresentAlreadyMatchesNoChange(t *testing.T) {
	withMockFileLabel(t, map[string]string{"/etc/foo": "system_u:object_r:etc_t:s0"}, nil, nil)

	s := SELinux{id: "t", method: "context_present", params: map[string]interface{}{
		"name": "/etc/foo", "context": "system_u:object_r:etc_t:s0",
	}}
	result, err := s.Apply(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Succeeded || result.Failed || result.Changed {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestContextPresentRelabels(t *testing.T) {
	calls := withMockFileLabel(t, map[string]string{"/etc/foo": "system_u:object_r:default_t:s0"}, nil, nil)

	s := SELinux{id: "t", method: "context_present", params: map[string]interface{}{
		"name": "/etc/foo", "context": "system_u:object_r:etc_t:s0", "recurse": true,
	}}
	result, err := s.Apply(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Succeeded || result.Failed || !result.Changed {
		t.Fatalf("unexpected result: %+v", result)
	}
	if len(*calls) != 1 {
		t.Fatalf("expected one chcon call, got %v", *calls)
	}
	if (*calls)[0].path != "/etc/foo" || (*calls)[0].label != "system_u:object_r:etc_t:s0" || !(*calls)[0].recurse {
		t.Fatalf("unexpected chcon call: %+v", (*calls)[0])
	}
}

func TestContextPresentTestModeDoesNotCallChcon(t *testing.T) {
	calls := withMockFileLabel(t, map[string]string{"/etc/foo": "system_u:object_r:default_t:s0"}, nil, nil)

	s := SELinux{id: "t", method: "context_present", params: map[string]interface{}{
		"name": "/etc/foo", "context": "system_u:object_r:etc_t:s0",
	}}
	result, err := s.Test(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Succeeded || result.Failed || !result.Changed {
		t.Fatalf("unexpected result: %+v", result)
	}
	if len(*calls) != 0 {
		t.Fatalf("expected no chcon calls in test mode, got %v", *calls)
	}
}

func TestContextPresentMissingContextError(t *testing.T) {
	s := SELinux{id: "t", method: "context_present", params: map[string]interface{}{"name": "/etc/foo"}}
	result, err := s.Apply(context.Background())
	if err == nil {
		t.Fatal("expected error for missing context")
	}
	if !result.Failed {
		t.Fatalf("expected Failed=true, got %+v", result)
	}
}

// TestContextPresentRejectsSilentDegrade mirrors the mode/boolean
// compliance concern: a chcon that reports success without the kernel
// actually applying the new label must not be reported as success.
func TestContextPresentRejectsSilentDegrade(t *testing.T) {
	withMockFileLabel(t, map[string]string{"/etc/foo": "system_u:object_r:default_t:s0"}, nil,
		func(requested string) string {
			return "system_u:object_r:default_t:s0" // kernel ignores the relabel
		})

	s := SELinux{id: "t", method: "context_present", params: map[string]interface{}{
		"name": "/etc/foo", "context": "system_u:object_r:etc_t:s0",
	}}
	result, err := s.Apply(context.Background())
	if err == nil {
		t.Fatal("expected an error when the verified label doesn't match the requested context")
	}
	if !result.Failed || result.Succeeded {
		t.Fatalf("expected Failed=true, Succeeded=false; got %+v", result)
	}
}
