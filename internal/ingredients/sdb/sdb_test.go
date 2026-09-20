package sdb

import (
	"context"
	"testing"
)

type stubProvider struct {
	value string
	err   error
	calls []string
}

func (s *stubProvider) Get(_ context.Context, ref string) (string, error) {
	s.calls = append(s.calls, ref)
	return s.value, s.err
}

func TestParseRef(t *testing.T) {
	cases := []struct {
		name        string
		ref         string
		wantBackend string
		wantPath    string
		wantFrag    string
		wantErr     bool
	}{
		{"basic", "sdb://openbao/secret/myapp/db", "openbao", "/secret/myapp/db", "", false},
		{"fragment", "sdb://openbao/secret/myapp/db#password", "openbao", "/secret/myapp/db", "password", false},
		{"wrong scheme", "https://openbao/secret", "", "", "", true},
		{"missing backend", "sdb:///secret", "", "", "", true},
		{"not a uri", "::not a uri::", "", "", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			backend, u, err := ParseRef(tc.ref)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected an error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if backend != tc.wantBackend {
				t.Errorf("backend = %q, want %q", backend, tc.wantBackend)
			}
			if u.Path != tc.wantPath {
				t.Errorf("path = %q, want %q", u.Path, tc.wantPath)
			}
			if u.Fragment != tc.wantFrag {
				t.Errorf("fragment = %q, want %q", u.Fragment, tc.wantFrag)
			}
		})
	}
}

func TestRegisterAndGet(t *testing.T) {
	resetRegistry(t)
	stub := &stubProvider{value: "shh"}
	if err := RegisterProvider("teststub", stub); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := Get(t.Context(), "sdb://teststub/whatever/path")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "shh" {
		t.Errorf("got %q, want %q", got, "shh")
	}
	if len(stub.calls) != 1 || stub.calls[0] != "sdb://teststub/whatever/path" {
		t.Errorf("expected the provider to receive the full ref, got %v", stub.calls)
	}
}

func TestRegisterProvider_Duplicate(t *testing.T) {
	resetRegistry(t)
	if err := RegisterProvider("dup", &stubProvider{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	err := RegisterProvider("dup", &stubProvider{})
	if err == nil {
		t.Fatal("expected an error registering a duplicate backend")
	}
}

func TestRegisterProvider_EmptyName(t *testing.T) {
	resetRegistry(t)
	if err := RegisterProvider("", &stubProvider{}); err == nil {
		t.Fatal("expected an error registering an empty backend name")
	}
}

func TestGet_UnknownBackend(t *testing.T) {
	resetRegistry(t)
	if _, err := Get(t.Context(), "sdb://nope/path"); err == nil {
		t.Fatal("expected an error for an unregistered backend")
	}
}

func TestSelectField(t *testing.T) {
	cases := []struct {
		name    string
		fields  map[string]string
		field   string
		want    string
		wantErr bool
	}{
		{"single field, no selector", map[string]string{"value": "v"}, "", "v", false},
		{"explicit field", map[string]string{"a": "1", "b": "2"}, "b", "2", false},
		{"ambiguous", map[string]string{"a": "1", "b": "2"}, "", "", true},
		{"missing field", map[string]string{"a": "1"}, "c", "", true},
		{"empty secret", map[string]string{}, "", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SelectField(tc.fields, tc.field)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected an error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// resetRegistry clears provMap around a test so RegisterProvider calls
// from other test files' init()-registered production providers (which
// run against real endpoints and shouldn't be exercised here) don't
// collide with the fixed test backend names used in this file.
func resetRegistry(t *testing.T) {
	t.Helper()
	provTex.Lock()
	saved := provMap
	provMap = make(map[string]SecretProvider)
	provTex.Unlock()
	t.Cleanup(func() {
		provTex.Lock()
		provMap = saved
		provTex.Unlock()
	})
}
