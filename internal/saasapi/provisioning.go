package saasapi

import (
	"context"

	"gorm.io/gorm"

	log "github.com/gogrlx/grlx/v2/internal/log"
)

// enqueueProvisioningJob writes an outbox row for an async tenant
// operation (design doc §4 "Async pattern") and, in a fully wired system,
// would trigger dispatch to farmer over NATS. It must be called within
// the same transaction as the Tenant row write so the outbox row and the
// tenant's pending/offboarding status can never diverge.
func enqueueProvisioningJob(tx *gorm.DB, tenantID string, jobType ProvisioningJobType) (*ProvisioningJob, error) {
	id, err := newID("pj_")
	if err != nil {
		return nil, err
	}
	job := &ProvisioningJob{
		ID:       id,
		TenantID: tenantID,
		Type:     jobType,
		Status:   ProvisioningJobPending,
	}
	if err := tx.Create(job).Error; err != nil {
		return nil, err
	}
	return job, nil
}

// dispatchProvisioning is called after the enclosing transaction commits.
// It is a stub: it does not publish anything to farmer yet.
//
// TODO(workstream B/H): publish internal.tenant.provision (design doc
// §2.2) once the privileged internal NATS identity (B) and the
// Envoy/enrollment subsystem (H) have landed, then consume
// internal.tenant.provisioned.{job_id} to move the ProvisioningJob (and
// the tenant's TenantStatus) from pending to active/failed. Until then,
// created tenants stay in TenantStatusPending indefinitely — that's
// expected for this scaffold, not a bug.
func dispatchProvisioning(_ context.Context, job *ProvisioningJob) {
	log.Warnf("saasapi: provisioning dispatch stubbed (job %s, tenant %s, type %s) — "+
		"internal.tenant.provision not implemented, see design doc §2.2", job.ID, job.TenantID, job.Type)
}

// dispatchDeprovisioning is the DELETE-path counterpart of
// dispatchProvisioning.
//
// TODO(workstream B/H): publish internal.tenant.deprovision (design doc
// §2.2); same caveat as dispatchProvisioning.
func dispatchDeprovisioning(_ context.Context, job *ProvisioningJob) {
	log.Warnf("saasapi: deprovisioning dispatch stubbed (job %s, tenant %s, type %s) — "+
		"internal.tenant.deprovision not implemented, see design doc §2.2", job.ID, job.TenantID, job.Type)
}
