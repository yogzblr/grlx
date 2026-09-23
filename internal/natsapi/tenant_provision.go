package natsapi

// Farmer's half of the SaaS API's tenant-provisioning bridge
// (cloudxp-machine-manager-api-design.md §2.2): internal.tenant.provision
// and internal.tenant.deprovision in, internal.tenant.provisioned.{job_id}
// and internal.tenant.deprovisioned.{job_id} out.
//
// Unlike every other registration in this package, these handlers are not
// per-tenant: they're platform-level control-plane subjects in the SYS
// Account, registered once per farmer process on its SYS listener
// connection (cmd/farmer/main.go's initSystemAccountListeners) — not on
// any tenant's connection, and not via Subscribe/routes, whose handlers
// all receive a connection-bound tenantID. See
// docs/design/grlx-internal-api-account.md for that decision. The only
// identity allowed to publish these request subjects (besides farmer's
// own SYS user) is the SaaS API's scoped SYS User
// (pki.EnsureSaaSAPICredential), so no per-message token/RBAC check
// applies here — authorization is the bus's own per-User permission
// check, the same way sprout-facing subjects are authorized.

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/nats-io/nats.go"

	"github.com/gogrlx/grlx/v2/internal/audit"
	"github.com/gogrlx/grlx/v2/internal/controlplane"
	log "github.com/gogrlx/grlx/v2/internal/log"
	"github.com/gogrlx/grlx/v2/internal/pki"
)

// provisionTenant/deprovisionTenant are indirections over pki's real
// functions so handler-level unit tests can exercise decode/validation/
// reply behavior without a full PKI+bus setup. Production code and the
// end-to-end test (internal/saasapi/provisioning_e2e_test.go) always run
// the real pki.ProvisionTenant/pki.DeprovisionTenant.
var (
	provisionTenant   = pki.ProvisionTenant
	deprovisionTenant = pki.DeprovisionTenant
)

// Audit action names for the two handlers, matching the subject names.
const (
	auditActionTenantProvision   = controlplane.SubjectTenantProvision
	auditActionTenantDeprovision = controlplane.SubjectTenantDeprovision
)

// RegisterTenantProvisioning queue-subscribes nc — farmer's SYS listener
// connection — to internal.tenant.provision and internal.tenant.deprovision.
// It uses the same natsCoreQueueGroup as grlx.api.> (workstream D's
// discipline) so that with several farmer replicas, exactly one processes
// each request. Call once per process, not once per tenant.
func RegisterTenantProvisioning(nc *nats.Conn) error {
	if _, err := nc.QueueSubscribe(controlplane.SubjectTenantProvision, natsCoreQueueGroup, func(msg *nats.Msg) {
		handleTenantProvision(nc, msg.Data)
	}); err != nil {
		return fmt.Errorf("natsapi: failed to subscribe to %s: %w", controlplane.SubjectTenantProvision, err)
	}
	if _, err := nc.QueueSubscribe(controlplane.SubjectTenantDeprovision, natsCoreQueueGroup, func(msg *nats.Msg) {
		handleTenantDeprovision(nc, msg.Data)
	}); err != nil {
		return fmt.Errorf("natsapi: failed to subscribe to %s: %w", controlplane.SubjectTenantDeprovision, err)
	}
	log.Info("natsapi: registered tenant provisioning handlers (SYS account)")
	return nil
}

func handleTenantProvision(nc *nats.Conn, data []byte) {
	var req controlplane.TenantProvisionRequest
	if err := json.Unmarshal(data, &req); err != nil {
		log.Errorf("natsapi: dropping malformed %s request: %v", controlplane.SubjectTenantProvision, err)
		return
	}
	// With no valid job ID there's no subject to report a result on — the
	// SaaS API's outbox row stays pending, which is the honest outcome.
	if !controlplane.ValidJobID(req.JobID) {
		log.Errorf("natsapi: dropping %s request with invalid job_id %q (tenant %q)", controlplane.SubjectTenantProvision, req.JobID, req.TenantID)
		return
	}

	res := controlplane.TenantResult{JobID: req.JobID, TenantID: req.TenantID, Status: controlplane.StatusActive}
	err := provisionTenant(req.TenantID, req.Name)
	if err != nil {
		// The full error stays here, keyed by job ID; only a fixed code
		// goes on the bus (see controlplane.ErrorCode).
		log.Errorf("natsapi: provisioning tenant %q (job %s) failed: %v", req.TenantID, req.JobID, err)
		res.Status = controlplane.StatusFailed
		res.ErrorCode = tenantErrorCode(err)
	}
	auditTenantAction(auditActionTenantProvision, data, res, err)
	publishTenantResult(nc, controlplane.ProvisionedSubject(req.JobID), res)
}

func handleTenantDeprovision(nc *nats.Conn, data []byte) {
	var req controlplane.TenantDeprovisionRequest
	if err := json.Unmarshal(data, &req); err != nil {
		log.Errorf("natsapi: dropping malformed %s request: %v", controlplane.SubjectTenantDeprovision, err)
		return
	}
	if !controlplane.ValidJobID(req.JobID) {
		log.Errorf("natsapi: dropping %s request with invalid job_id %q (tenant %q)", controlplane.SubjectTenantDeprovision, req.JobID, req.TenantID)
		return
	}

	res := controlplane.TenantResult{JobID: req.JobID, TenantID: req.TenantID, Status: controlplane.StatusOffboarded}
	err := deprovisionTenant(req.TenantID)
	if err != nil {
		log.Errorf("natsapi: deprovisioning tenant %q (job %s) failed: %v", req.TenantID, req.JobID, err)
		res.Status = controlplane.StatusFailed
		res.ErrorCode = tenantErrorCode(err)
	}
	auditTenantAction(auditActionTenantDeprovision, data, res, err)
	publishTenantResult(nc, controlplane.DeprovisionedSubject(req.JobID), res)
}

// tenantErrorCode maps a pki provisioning error to the fixed code
// published on the bus. Only pki's own sentinel errors get a specific
// code; everything else — wrapped filesystem, database and resolver-push
// errors, whose text can carry paths and internal detail — is
// ErrorInternal.
func tenantErrorCode(err error) controlplane.ErrorCode {
	switch {
	case errors.Is(err, pki.ErrTenantIDInvalid):
		return controlplane.ErrorInvalidTenantID
	case errors.Is(err, pki.ErrTenantNotFound):
		return controlplane.ErrorTenantNotFound
	default:
		return controlplane.ErrorInternal
	}
}

func publishTenantResult(nc *nats.Conn, subject string, res controlplane.TenantResult) {
	data, err := json.Marshal(res)
	if err != nil {
		log.Errorf("natsapi: marshalling result for %s: %v", subject, err)
		return
	}
	if err := nc.Publish(subject, data); err != nil {
		log.Errorf("natsapi: publishing %s: %v", subject, err)
	}
}

func auditTenantAction(action string, params []byte, result any, err error) {
	if !audit.ShouldLog(action) {
		return
	}
	if auditErr := audit.LogAction(action, params, result, err); auditErr != nil {
		log.Errorf("natsapi: audit log failed for %s: %v", action, auditErr)
	}
}
