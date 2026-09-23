package saasapi

import "time"

// TenantStatus is the tenant lifecycle state exposed by GET
// /tenants/{tenant_id}/status (design doc §1.1).
type TenantStatus string

const (
	TenantStatusPending     TenantStatus = "pending"
	TenantStatusActive      TenantStatus = "active"
	TenantStatusFailed      TenantStatus = "failed"
	TenantStatusOffboarding TenantStatus = "offboarding"
	TenantStatusOffboarded  TenantStatus = "offboarded"
)

// Tenant is the `saas.tenants` table (design doc §4.2).
type Tenant struct {
	ID        string       `gorm:"column:id;primaryKey;size:32" json:"tenant_id"`
	Name      string       `gorm:"column:name;size:255;not null" json:"name"`
	Status    TenantStatus `gorm:"column:status;size:32;not null;index" json:"status"`
	PlanID    string       `gorm:"column:plan_id;size:64" json:"plan_id,omitempty"`
	CreatedAt time.Time    `gorm:"column:created_at" json:"created_at"`
	UpdatedAt time.Time    `gorm:"column:updated_at" json:"updated_at"`
}

func (Tenant) TableName() string { return "tenants" }

// ProvisioningJobType distinguishes tenant provisioning from deprovisioning
// (offboarding) outbox rows.
type ProvisioningJobType string

const (
	ProvisioningJobProvision   ProvisioningJobType = "provision"
	ProvisioningJobDeprovision ProvisioningJobType = "deprovision"
)

// ProvisioningJobStatus is the outbox row's own status, independent of
// (but driving) the tenant's TenantStatus.
type ProvisioningJobStatus string

const (
	ProvisioningJobPending   ProvisioningJobStatus = "pending"
	ProvisioningJobSucceeded ProvisioningJobStatus = "succeeded"
	ProvisioningJobFailed    ProvisioningJobStatus = "failed"
)

// ProvisioningJob is the `saas.provisioning_jobs` outbox table (design doc
// §4.2, §4 "Async pattern"). Every async tenant operation (create/delete)
// writes a row here rather than relying on a bare NATS publish, since NATS
// core (no JetStream) gives no redelivery guarantee.
//
// provisioning.go's applyProvisioningResult moves a job out of "pending"
// when farmer's internal.tenant.{de,}provisioned.{job_id} result arrives
// (§2.2); Attempts counts dispatches, for a future re-dispatch sweeper to
// bound on (see docs/design/grlx-internal-api-account.md).
type ProvisioningJob struct {
	ID        string                `gorm:"column:id;primaryKey;size:36" json:"id"`
	TenantID  string                `gorm:"column:tenant_id;size:32;not null;index" json:"tenant_id"`
	Type      ProvisioningJobType   `gorm:"column:type;size:32;not null" json:"type"`
	Status    ProvisioningJobStatus `gorm:"column:status;size:32;not null" json:"status"`
	Attempts  int                   `gorm:"column:attempts;not null;default:0" json:"attempts"`
	LastError string                `gorm:"column:last_error;type:text" json:"last_error,omitempty"`
	// Warning qualifies a succeeded job: a fixed, caller-safe message
	// (controlplane.PublicWarningMessage) for a result that reached its end
	// state by an unusual path — e.g. deprovisioning a tenant farmer never
	// provisioned. Surfaced by GET /tenants/{id}/status.
	Warning   string    `gorm:"column:warning;type:text" json:"warning,omitempty"`
	CreatedAt time.Time `gorm:"column:created_at" json:"created_at"`
	UpdatedAt time.Time `gorm:"column:updated_at" json:"updated_at"`
}

func (ProvisioningJob) TableName() string { return "provisioning_jobs" }

// EnrollmentKey is the `saas.enrollment_keys` table (design doc §4.2,
// §3.1). Only key_id is ever stored in plaintext; the secret half of the
// issued token is stored solely as its SHA-256 hash (KeyHash) — see
// idgen.go/enrollment_keys.go, both explicitly flagged for security
// review per the task brief.
type EnrollmentKey struct {
	// KeyID is the public, indexed lookup half of the {key_id}.{secret}
	// token (§3.1) — safe to log and store in plaintext.
	KeyID      string     `gorm:"column:key_id;primaryKey;size:32" json:"key_id"`
	TenantID   string     `gorm:"column:tenant_id;size:32;not null;index" json:"tenant_id"`
	KeyHash    string     `gorm:"column:key_hash;size:64;not null" json:"-"`
	Expiry     time.Time  `gorm:"column:expiry;not null" json:"expires_at"`
	MaxUses    int        `gorm:"column:max_uses;not null" json:"max_uses"`
	UsedCount  int        `gorm:"column:used_count;not null;default:0" json:"used_count"`
	Revoked    bool       `gorm:"column:revoked;not null;default:false" json:"revoked"`
	CreatedAt  time.Time  `gorm:"column:created_at" json:"created_at"`
	LastUsedAt *time.Time `gorm:"column:last_used_at" json:"last_used_at,omitempty"`
}

func (EnrollmentKey) TableName() string { return "enrollment_keys" }
