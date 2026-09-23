package controlplane

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestValidJobID(t *testing.T) {
	valid := []string{"pj_abc123", "PJ-9", "a", strings.Repeat("x", 36)}
	for _, id := range valid {
		if !ValidJobID(id) {
			t.Errorf("ValidJobID(%q) = false, want true", id)
		}
	}
	invalid := []string{"", "pj.abc", "pj_*", "pj_>", "pj abc", "pj\tabc", "pj_é", strings.Repeat("x", 37)}
	for _, id := range invalid {
		if ValidJobID(id) {
			t.Errorf("ValidJobID(%q) = true, want false", id)
		}
	}
}

func TestResultSubjectsRoundTrip(t *testing.T) {
	if got := ProvisionedSubject("pj_1"); got != "internal.tenant.provisioned.pj_1" {
		t.Fatalf("ProvisionedSubject = %q", got)
	}
	if got := DeprovisionedSubject("pj_1"); got != "internal.tenant.deprovisioned.pj_1" {
		t.Fatalf("DeprovisionedSubject = %q", got)
	}
	id, ok := JobIDFromSubject(ProvisionedSubject("pj_1"), SubjectTenantProvisionedPrefix)
	if !ok || id != "pj_1" {
		t.Fatalf("JobIDFromSubject = %q, %v", id, ok)
	}
	// A deprovision result must not parse as a provision result.
	if _, ok := JobIDFromSubject(DeprovisionedSubject("pj_1"), SubjectTenantProvisionedPrefix); ok {
		t.Fatal("expected a deprovisioned subject not to match the provisioned prefix")
	}
	if _, ok := JobIDFromSubject(SubjectTenantProvisionedPrefix+"a.b", SubjectTenantProvisionedPrefix); ok {
		t.Fatal("expected a multi-token suffix to be rejected")
	}
}

func TestTruncateError(t *testing.T) {
	short := "boom"
	if got := TruncateError(short); got != short {
		t.Fatalf("TruncateError(short) = %q", got)
	}
	// 'é' is two bytes; make the MaxErrorLen boundary land mid-rune.
	long := "x" + strings.Repeat("é", MaxErrorLen)
	got := TruncateError(long)
	if len(got) > MaxErrorLen {
		t.Fatalf("len = %d, want <= %d", len(got), MaxErrorLen)
	}
	if !utf8.ValidString(got) {
		t.Fatal("truncation split a UTF-8 sequence")
	}
}
