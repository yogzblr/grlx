package saasapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func doRequest(t *testing.T, h http.HandlerFunc, method, path string, pathValues map[string]string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encoding request body: %v", err)
		}
	}
	r := httptest.NewRequest(method, path, &buf)
	for k, v := range pathValues {
		r.SetPathValue(k, v)
	}
	w := httptest.NewRecorder()
	h(w, r)
	return w
}

func TestCreateTenant(t *testing.T) {
	gdb := newTestDB(t)

	w := doRequest(t, CreateTenant, "POST", "/v1/tenants", nil, createTenantRequest{Name: "Acme Bank", PlanID: "plan_std"})
	if w.Code != 202 {
		t.Fatalf("status = %d, want 202, body=%s", w.Code, w.Body.String())
	}

	var resp tenantStatusResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if resp.Status != TenantStatusPending {
		t.Fatalf("status = %q, want pending", resp.Status)
	}
	if resp.TenantID == "" {
		t.Fatalf("expected a non-empty tenant_id")
	}

	var job ProvisioningJob
	if err := gdb.Where("tenant_id = ?", resp.TenantID).First(&job).Error; err != nil {
		t.Fatalf("expected a provisioning_jobs row: %v", err)
	}
	if job.Type != ProvisioningJobProvision || job.Status != ProvisioningJobPending {
		t.Fatalf("unexpected job %+v", job)
	}
}

func TestCreateTenantMissingName(t *testing.T) {
	newTestDB(t)
	w := doRequest(t, CreateTenant, "POST", "/v1/tenants", nil, createTenantRequest{PlanID: "plan_std"})
	if w.Code != 400 {
		t.Fatalf("status = %d, want 400, body=%s", w.Code, w.Body.String())
	}
	var errResp errorResponse
	json.Unmarshal(w.Body.Bytes(), &errResp)
	if errResp.Error != "invalid_request" {
		t.Fatalf("error code = %q, want invalid_request", errResp.Error)
	}
}

func mustCreateTenant(t *testing.T, name string) string {
	t.Helper()
	w := doRequest(t, CreateTenant, "POST", "/v1/tenants", nil, createTenantRequest{Name: name})
	if w.Code != 202 {
		t.Fatalf("creating tenant: status = %d, body=%s", w.Code, w.Body.String())
	}
	var resp tenantStatusResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	return resp.TenantID
}

func TestGetTenant(t *testing.T) {
	newTestDB(t)
	id := mustCreateTenant(t, "Acme Bank")

	w := doRequest(t, GetTenant, "GET", "/v1/tenants/"+id, map[string]string{"tenant_id": id}, nil)
	if w.Code != 200 {
		t.Fatalf("status = %d, want 200, body=%s", w.Code, w.Body.String())
	}
	var tenant Tenant
	json.Unmarshal(w.Body.Bytes(), &tenant)
	if tenant.Name != "Acme Bank" {
		t.Fatalf("name = %q, want Acme Bank", tenant.Name)
	}
}

func TestGetTenantNotFound(t *testing.T) {
	newTestDB(t)
	w := doRequest(t, GetTenant, "GET", "/v1/tenants/nope", map[string]string{"tenant_id": "nope"}, nil)
	if w.Code != 404 {
		t.Fatalf("status = %d, want 404, body=%s", w.Code, w.Body.String())
	}
	var errResp errorResponse
	json.Unmarshal(w.Body.Bytes(), &errResp)
	if errResp.Error != "tenant_not_found" {
		t.Fatalf("error code = %q, want tenant_not_found", errResp.Error)
	}
}

func TestPatchTenant(t *testing.T) {
	newTestDB(t)
	id := mustCreateTenant(t, "Acme Bank")

	newName := "Acme Bank International"
	w := doRequest(t, PatchTenant, "PATCH", "/v1/tenants/"+id, map[string]string{"tenant_id": id}, patchTenantRequest{Name: &newName})
	if w.Code != 200 {
		t.Fatalf("status = %d, want 200, body=%s", w.Code, w.Body.String())
	}
	var tenant Tenant
	json.Unmarshal(w.Body.Bytes(), &tenant)
	if tenant.Name != newName {
		t.Fatalf("name = %q, want %q", tenant.Name, newName)
	}
}

func TestPatchTenantNoFields(t *testing.T) {
	newTestDB(t)
	id := mustCreateTenant(t, "Acme Bank")

	w := doRequest(t, PatchTenant, "PATCH", "/v1/tenants/"+id, map[string]string{"tenant_id": id}, patchTenantRequest{})
	if w.Code != 400 {
		t.Fatalf("status = %d, want 400, body=%s", w.Code, w.Body.String())
	}
}

func TestDeleteTenant(t *testing.T) {
	gdb := newTestDB(t)
	id := mustCreateTenant(t, "Acme Bank")

	w := doRequest(t, DeleteTenant, "DELETE", "/v1/tenants/"+id, map[string]string{"tenant_id": id}, nil)
	if w.Code != 202 {
		t.Fatalf("status = %d, want 202, body=%s", w.Code, w.Body.String())
	}
	var resp tenantStatusResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Status != TenantStatusOffboarding {
		t.Fatalf("status = %q, want offboarding", resp.Status)
	}

	var job ProvisioningJob
	if err := gdb.Where("tenant_id = ? AND type = ?", id, ProvisioningJobDeprovision).First(&job).Error; err != nil {
		t.Fatalf("expected a deprovision job: %v", err)
	}

	// A second delete while already offboarding must conflict, not
	// silently enqueue a second deprovision job.
	w2 := doRequest(t, DeleteTenant, "DELETE", "/v1/tenants/"+id, map[string]string{"tenant_id": id}, nil)
	if w2.Code != 409 {
		t.Fatalf("second delete status = %d, want 409, body=%s", w2.Code, w2.Body.String())
	}
}

func TestGetTenantStatus(t *testing.T) {
	newTestDB(t)
	id := mustCreateTenant(t, "Acme Bank")

	w := doRequest(t, GetTenantStatus, "GET", "/v1/tenants/"+id+"/status", map[string]string{"tenant_id": id}, nil)
	if w.Code != 200 {
		t.Fatalf("status = %d, want 200, body=%s", w.Code, w.Body.String())
	}
	var resp tenantStatusResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Status != TenantStatusPending {
		t.Fatalf("status = %q, want pending", resp.Status)
	}
	if resp.LastError != "" {
		t.Fatalf("expected no last_error for a freshly created tenant, got %q", resp.LastError)
	}
}
