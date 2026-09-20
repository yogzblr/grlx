package saasapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"gorm.io/gorm"
)

type createTenantRequest struct {
	Name   string `json:"name"`
	PlanID string `json:"plan_id"`
}

type tenantStatusResponse struct {
	TenantID  string       `json:"tenant_id"`
	Status    TenantStatus `json:"status"`
	LastError string       `json:"last_error,omitempty"`
}

// CreateTenant handles POST /tenants (design doc §1.1). It's async: the
// tenant row is created with status "pending" and a provisioning_jobs
// outbox row is written in the same transaction, then dispatch to farmer
// is attempted (currently stubbed — see provisioning.go). The response is
// 202 Accepted, never 201, since provisioning isn't complete yet.
func CreateTenant(w http.ResponseWriter, r *http.Request) {
	var req createTenantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body must be valid JSON")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "name is required")
		return
	}

	tenantID, err := newID("t_")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to generate tenant id")
		return
	}
	tenant := Tenant{
		ID:     tenantID,
		Name:   req.Name,
		Status: TenantStatusPending,
		PlanID: req.PlanID,
	}

	var job *ProvisioningJob
	err = db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&tenant).Error; err != nil {
			return err
		}
		var jobErr error
		job, jobErr = enqueueProvisioningJob(tx, tenant.ID, ProvisioningJobProvision)
		return jobErr
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to create tenant")
		return
	}

	dispatchProvisioning(r.Context(), job)

	writeJSON(w, http.StatusAccepted, tenantStatusResponse{TenantID: tenant.ID, Status: tenant.Status})
}

// GetTenant handles GET /tenants/{tenant_id} (design doc §1.1).
func GetTenant(w http.ResponseWriter, r *http.Request) {
	tenant, ok := lookupTenant(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, tenant)
}

type patchTenantRequest struct {
	Name   *string `json:"name"`
	PlanID *string `json:"plan_id"`
}

// PatchTenant handles PATCH /tenants/{tenant_id} (design doc §1.1),
// updating name/plan. The design doc also mentions "metadata" in prose,
// but §4.2's schema sketch has no metadata column on `saas.tenants` —
// deliberately left out here rather than inventing schema beyond what's
// specified; see the PR description.
func PatchTenant(w http.ResponseWriter, r *http.Request) {
	tenant, ok := lookupTenant(w, r)
	if !ok {
		return
	}

	var req patchTenantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body must be valid JSON")
		return
	}

	updates := map[string]any{}
	if req.Name != nil {
		name := strings.TrimSpace(*req.Name)
		if name == "" {
			writeError(w, http.StatusBadRequest, "invalid_request", "name cannot be empty")
			return
		}
		updates["name"] = name
	}
	if req.PlanID != nil {
		updates["plan_id"] = *req.PlanID
	}
	if len(updates) == 0 {
		writeError(w, http.StatusBadRequest, "invalid_request", "no updatable fields provided")
		return
	}

	if err := db.Model(&tenant).Updates(updates).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to update tenant")
		return
	}
	if err := db.First(&tenant, "id = ?", tenant.ID).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to reload tenant")
		return
	}
	writeJSON(w, http.StatusOK, tenant)
}

// DeleteTenant handles DELETE /tenants/{tenant_id} (design doc §1.1) —
// offboarding follows the same async create-row-then-poll pattern as
// CreateTenant.
func DeleteTenant(w http.ResponseWriter, r *http.Request) {
	tenant, ok := lookupTenant(w, r)
	if !ok {
		return
	}
	if tenant.Status == TenantStatusOffboarding || tenant.Status == TenantStatusOffboarded {
		writeError(w, http.StatusConflict, "offboarding_in_progress", "tenant is already offboarding or offboarded")
		return
	}

	var job *ProvisioningJob
	err := db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&tenant).Update("status", TenantStatusOffboarding).Error; err != nil {
			return err
		}
		var jobErr error
		job, jobErr = enqueueProvisioningJob(tx, tenant.ID, ProvisioningJobDeprovision)
		return jobErr
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to start tenant offboarding")
		return
	}

	dispatchDeprovisioning(r.Context(), job)

	writeJSON(w, http.StatusAccepted, tenantStatusResponse{TenantID: tenant.ID, Status: TenantStatusOffboarding})
}

// GetTenantStatus handles GET /tenants/{tenant_id}/status (design doc
// §1.1) — a lightweight status-only poll, including the last provisioning
// error if the most recent outbox job for this tenant failed.
func GetTenantStatus(w http.ResponseWriter, r *http.Request) {
	tenant, ok := lookupTenant(w, r)
	if !ok {
		return
	}

	resp := tenantStatusResponse{TenantID: tenant.ID, Status: tenant.Status}
	if tenant.Status == TenantStatusFailed || tenant.Status == TenantStatusOffboarding {
		var job ProvisioningJob
		err := db.Where("tenant_id = ?", tenant.ID).Order("created_at DESC").First(&job).Error
		if err == nil && job.Status == ProvisioningJobFailed {
			resp.LastError = job.LastError
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func lookupTenant(w http.ResponseWriter, r *http.Request) (Tenant, bool) {
	tenantID := r.PathValue("tenant_id")
	var tenant Tenant
	err := db.First(&tenant, "id = ?", tenantID).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		writeError(w, http.StatusNotFound, "tenant_not_found", "no such tenant")
		return Tenant{}, false
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to look up tenant")
		return Tenant{}, false
	}
	return tenant, true
}
