package saasapi

import "net/http"

// NewRouter builds the SaaS API's HTTP router (design doc §1.1, §1.2).
// Every route is wrapped in Auth — see middleware.go for what that
// currently does and does not check.
func NewRouter() *http.ServeMux {
	mux := http.NewServeMux()

	route(mux, "POST /v1/tenants", CreateTenant, "CreateTenant")
	route(mux, "GET /v1/tenants/{tenant_id}", GetTenant, "GetTenant")
	route(mux, "PATCH /v1/tenants/{tenant_id}", PatchTenant, "PatchTenant")
	route(mux, "DELETE /v1/tenants/{tenant_id}", DeleteTenant, "DeleteTenant")
	route(mux, "GET /v1/tenants/{tenant_id}/status", GetTenantStatus, "GetTenantStatus")

	route(mux, "POST /v1/tenants/{tenant_id}/enrollment-keys", CreateEnrollmentKey, "CreateEnrollmentKey")
	route(mux, "GET /v1/tenants/{tenant_id}/enrollment-keys", ListEnrollmentKeys, "ListEnrollmentKeys")
	route(mux, "DELETE /v1/tenants/{tenant_id}/enrollment-keys/{key_id}", DeleteEnrollmentKey, "DeleteEnrollmentKey")

	return mux
}

func route(mux *http.ServeMux, pattern string, h http.HandlerFunc, name string) {
	mux.Handle(pattern, Logger(Auth(h, name), name))
}
