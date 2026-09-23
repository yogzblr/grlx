package controlplane

import (
	"strings"
	"testing"
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

func TestPublicErrorMessage(t *testing.T) {
	for _, code := range []ErrorCode{ErrorInvalidTenantID, ErrorTenantNotFound, ErrorInternal} {
		if PublicErrorMessage(code) == "" {
			t.Errorf("no public message for %q", code)
		}
	}
	// Anything unrecognized — including text that looks like a leaked
	// error — maps to the generic message, never echoed back.
	leaked := ErrorCode("mkdir /etc/grlx/pki/nats-auth/tenants: not a directory")
	if got := PublicErrorMessage(leaked); got != PublicErrorMessage(ErrorInternal) {
		t.Fatalf("PublicErrorMessage(unknown) = %q, want the internal-error message", got)
	}
	if got := PublicErrorMessage(""); got != PublicErrorMessage(ErrorInternal) {
		t.Fatalf("PublicErrorMessage(\"\") = %q", got)
	}
}
