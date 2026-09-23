// Package controlplane is the wire contract for the platform-level
// internal.* NATS subjects between the SaaS API (internal/saasapi) and
// farmer (internal/natsapi) — cloudxp-machine-manager-api-design.md §2.2.
// It holds only subject names, message shapes, and validation, and has no
// dependencies of its own, so that both sides — and internal/pki, which
// scopes the SaaS API's NATS User permissions to exactly these subjects —
// can share one definition without internal/saasapi pulling in farmer's
// whole dependency tree.
//
// These subjects live in the SYS Account, not any tenant's: see
// docs/design/grlx-internal-api-account.md for that decision and why.
package controlplane

import "strings"

// Request subjects, published by the SaaS API and queue-subscribed by
// farmer. Fire-and-forget (design doc §2.2): no NATS reply is expected;
// the outcome comes back on the matching per-job result subject below.
const (
	SubjectTenantProvision   = "internal.tenant.provision"
	SubjectTenantDeprovision = "internal.tenant.deprovision"
)

// Result subject prefixes, published by farmer with the job's ID as the
// final token (e.g. internal.tenant.provisioned.pj_abc123) and subscribed
// by the SaaS API via the single-token wildcards below.
const (
	SubjectTenantProvisionedPrefix   = "internal.tenant.provisioned."
	SubjectTenantDeprovisionedPrefix = "internal.tenant.deprovisioned."

	SubjectTenantProvisionedWildcard   = SubjectTenantProvisionedPrefix + "*"
	SubjectTenantDeprovisionedWildcard = SubjectTenantDeprovisionedPrefix + "*"
)

// Result statuses farmer reports. A provision succeeds as StatusActive; a
// deprovision succeeds as StatusOffboarded; either can fail as
// StatusFailed with Error set.
const (
	StatusActive     = "active"
	StatusOffboarded = "offboarded"
	StatusFailed     = "failed"
)

// MaxErrorLen bounds TenantResult.Error, so a pathological error string
// can't bloat a NATS message or the saas.provisioning_jobs row it's
// recorded into.
const MaxErrorLen = 1024

// TenantProvisionRequest is the internal.tenant.provision payload.
type TenantProvisionRequest struct {
	JobID    string `json:"job_id"`
	TenantID string `json:"tenant_id"`
	Name     string `json:"name"`
}

// TenantDeprovisionRequest is the internal.tenant.deprovision payload.
type TenantDeprovisionRequest struct {
	JobID    string `json:"job_id"`
	TenantID string `json:"tenant_id"`
}

// TenantResult is the payload of both internal.tenant.provisioned.{job_id}
// and internal.tenant.deprovisioned.{job_id}.
type TenantResult struct {
	JobID    string `json:"job_id"`
	TenantID string `json:"tenant_id"`
	Status   string `json:"status"`
	Error    string `json:"error,omitempty"`
}

// maxJobIDLen matches saas.provisioning_jobs.id's column size.
const maxJobIDLen = 36

// ValidJobID reports whether id is safe to use as a single NATS subject
// token: non-empty, bounded, and restricted to [0-9A-Za-z_-]. Farmer builds
// the result subject by appending the request's job_id, so without this a
// crafted job_id containing '.' (an extra token), '*'/'>' (wildcards,
// rejected by the server on publish anyway) or whitespace could publish a
// result somewhere other than the one subject the SaaS API is waiting on.
func ValidJobID(id string) bool {
	if id == "" || len(id) > maxJobIDLen {
		return false
	}
	for _, r := range id {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

// ProvisionedSubject returns the result subject for a provision job.
// jobID must already satisfy ValidJobID.
func ProvisionedSubject(jobID string) string { return SubjectTenantProvisionedPrefix + jobID }

// DeprovisionedSubject returns the result subject for a deprovision job.
// jobID must already satisfy ValidJobID.
func DeprovisionedSubject(jobID string) string { return SubjectTenantDeprovisionedPrefix + jobID }

// JobIDFromSubject extracts the trailing job-ID token from a result
// subject received on one of the wildcards above, reporting false if the
// subject doesn't carry prefix or its remaining token isn't a valid job ID.
func JobIDFromSubject(subject, prefix string) (string, bool) {
	id, ok := strings.CutPrefix(subject, prefix)
	if !ok || !ValidJobID(id) {
		return "", false
	}
	return id, true
}

// TruncateError bounds an error message to MaxErrorLen bytes, never
// splitting a multi-byte UTF-8 sequence.
func TruncateError(msg string) string {
	if len(msg) <= MaxErrorLen {
		return msg
	}
	cut := MaxErrorLen
	for cut > 0 && !isRuneStart(msg[cut]) {
		cut--
	}
	return msg[:cut]
}

func isRuneStart(b byte) bool { return b&0xC0 != 0x80 }
