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

// ErrorCode classifies a failed provisioning result. Farmer never puts raw
// error text on the bus: a pki error can carry filesystem paths, key file
// names, or database detail, and the SaaS API relays a failed job's error
// to its external callers (GET /tenants/{id}/status). Farmer logs the full
// error locally, keyed by job ID; only one of these fixed codes crosses the
// service boundary, and the SaaS API only ever displays PublicErrorMessage
// for it.
type ErrorCode string

const (
	// ErrorInvalidTenantID: farmer rejected the tenant ID's format.
	ErrorInvalidTenantID ErrorCode = "invalid_tenant_id"
	// ErrorTenantNotFound: farmer has no record of the tenant (e.g. a
	// deprovision for a tenant that was never provisioned).
	ErrorTenantNotFound ErrorCode = "tenant_not_found"
	// ErrorInternal: anything else. The detail stays in farmer's logs.
	ErrorInternal ErrorCode = "internal_error"
)

var publicErrorMessages = map[ErrorCode]string{
	ErrorInvalidTenantID: "the tenant ID was rejected by the provisioning service",
	ErrorTenantNotFound:  "the tenant is not known to the provisioning service",
	ErrorInternal:        "an internal error occurred during provisioning; retry or contact support",
}

// PublicErrorMessage returns the fixed, caller-safe message for code. An
// unrecognized code (a newer farmer, or a malformed result) maps to the
// ErrorInternal message rather than being echoed back, so nothing a
// result carries is ever displayed verbatim.
func PublicErrorMessage(code ErrorCode) string {
	if msg, ok := publicErrorMessages[code]; ok {
		return msg
	}
	return publicErrorMessages[ErrorInternal]
}

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
// and internal.tenant.deprovisioned.{job_id}. A failure carries only an
// ErrorCode, never error text — see ErrorCode.
type TenantResult struct {
	JobID     string    `json:"job_id"`
	TenantID  string    `json:"tenant_id"`
	Status    string    `json:"status"`
	ErrorCode ErrorCode `json:"error_code,omitempty"`
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
