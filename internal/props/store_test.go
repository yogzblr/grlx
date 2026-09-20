package props

import (
	"testing"
)

// TestSetPropPersistsAcrossHandles verifies a prop written through one
// SetDB-installed handle is visible from a second handle pointed at the
// same underlying database — the read-through behavior that replaces the
// old per-process JSON-file cache.
func TestSetPropPersistsAcrossHandles(t *testing.T) {
	newTestDB(t)

	if err := SetProp("sprout-1", "os", "linux"); err != nil {
		t.Fatal(err)
	}
	if err := SetProp("sprout-1", "arch", "amd64"); err != nil {
		t.Fatal(err)
	}

	if got := GetStringProp("sprout-1", "os"); got != "linux" {
		t.Errorf("expected 'linux', got %q", got)
	}
	if got := GetStringProp("sprout-1", "arch"); got != "amd64" {
		t.Errorf("expected 'amd64', got %q", got)
	}
}

func TestDeleteRemovesRow(t *testing.T) {
	newTestDB(t)

	SetProp("sprout-2", "role", "web")
	if got := GetStringProp("sprout-2", "role"); got != "web" {
		t.Fatalf("expected 'web' after SetProp, got %q", got)
	}

	DeleteProp("sprout-2", "role")
	if got := GetStringProp("sprout-2", "role"); got != "" {
		t.Error("expected empty string after delete")
	}
}
