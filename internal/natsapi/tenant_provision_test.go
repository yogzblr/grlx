package natsapi

// Handler-level coverage for tenant_provision.go: decode/validation/reply
// behavior and the queue-group discipline, with pki's functions stubbed.
// The whole chain — SaaS API HTTP handler, real pki.ProvisionTenant, the
// scoped SYS credential, and the saas schema status transition — is
// covered end to end in internal/saasapi/provisioning_e2e_test.go.

import (
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/gogrlx/grlx/v2/internal/controlplane"
)

func stubTenantProvisioning(t *testing.T, provision func(string, string) error, deprovision func(string) error) {
	t.Helper()
	origP, origD := provisionTenant, deprovisionTenant
	provisionTenant, deprovisionTenant = provision, deprovision
	t.Cleanup(func() { provisionTenant, deprovisionTenant = origP, origD })
}

func nextResult(t *testing.T, sub *nats.Subscription) controlplane.TenantResult {
	t.Helper()
	msg, err := sub.NextMsg(2 * time.Second)
	if err != nil {
		t.Fatalf("waiting for result: %v", err)
	}
	var res controlplane.TenantResult
	if err := json.Unmarshal(msg.Data, &res); err != nil {
		t.Fatalf("decoding result: %v", err)
	}
	return res
}

func publishJSON(t *testing.T, nc *nats.Conn, subject string, v any) {
	t.Helper()
	data, _ := json.Marshal(v)
	if err := nc.Publish(subject, data); err != nil {
		t.Fatalf("publish %s: %v", subject, err)
	}
	if err := nc.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
}

func TestTenantProvision_SuccessPublishesActive(t *testing.T) {
	nc, cleanup := startEmbeddedNATS(t)
	defer cleanup()
	var gotID, gotName string
	stubTenantProvisioning(t, func(id, name string) error { gotID, gotName = id, name; return nil }, nil)

	if err := RegisterTenantProvisioning(nc); err != nil {
		t.Fatalf("RegisterTenantProvisioning: %v", err)
	}
	sub, _ := nc.SubscribeSync(controlplane.ProvisionedSubject("pj_ok"))
	publishJSON(t, nc, controlplane.SubjectTenantProvision, controlplane.TenantProvisionRequest{JobID: "pj_ok", TenantID: "t_1", Name: "Acme"})

	res := nextResult(t, sub)
	if res.Status != controlplane.StatusActive || res.JobID != "pj_ok" || res.TenantID != "t_1" || res.Error != "" {
		t.Fatalf("unexpected result %+v", res)
	}
	if gotID != "t_1" || gotName != "Acme" {
		t.Fatalf("ProvisionTenant called with (%q, %q)", gotID, gotName)
	}
}

func TestTenantProvision_FailurePublishesFailedWithError(t *testing.T) {
	nc, cleanup := startEmbeddedNATS(t)
	defer cleanup()
	stubTenantProvisioning(t, func(string, string) error { return errors.New("resolver unreachable") }, nil)

	if err := RegisterTenantProvisioning(nc); err != nil {
		t.Fatalf("RegisterTenantProvisioning: %v", err)
	}
	sub, _ := nc.SubscribeSync(controlplane.ProvisionedSubject("pj_bad"))
	publishJSON(t, nc, controlplane.SubjectTenantProvision, controlplane.TenantProvisionRequest{JobID: "pj_bad", TenantID: "t_1"})

	res := nextResult(t, sub)
	if res.Status != controlplane.StatusFailed || res.Error != "resolver unreachable" {
		t.Fatalf("unexpected result %+v", res)
	}
}

func TestTenantDeprovision_SuccessAndFailure(t *testing.T) {
	nc, cleanup := startEmbeddedNATS(t)
	defer cleanup()
	stubTenantProvisioning(t, nil, func(id string) error {
		if id == "t_missing" {
			return errors.New("no such tenant")
		}
		return nil
	})

	if err := RegisterTenantProvisioning(nc); err != nil {
		t.Fatalf("RegisterTenantProvisioning: %v", err)
	}
	sub, _ := nc.SubscribeSync(controlplane.SubjectTenantDeprovisionedWildcard)

	publishJSON(t, nc, controlplane.SubjectTenantDeprovision, controlplane.TenantDeprovisionRequest{JobID: "pj_d1", TenantID: "t_1"})
	if res := nextResult(t, sub); res.Status != controlplane.StatusOffboarded || res.JobID != "pj_d1" {
		t.Fatalf("unexpected result %+v", res)
	}
	publishJSON(t, nc, controlplane.SubjectTenantDeprovision, controlplane.TenantDeprovisionRequest{JobID: "pj_d2", TenantID: "t_missing"})
	if res := nextResult(t, sub); res.Status != controlplane.StatusFailed || res.Error != "no such tenant" {
		t.Fatalf("unexpected result %+v", res)
	}
}

// TestTenantProvision_DropsInvalidJobIDAndMalformedJSON: neither case has
// a safe subject to reply on, so nothing is published and pki is never
// called — in particular a job_id with an extra token must not steer the
// result onto some other subject.
func TestTenantProvision_DropsInvalidJobIDAndMalformedJSON(t *testing.T) {
	nc, cleanup := startEmbeddedNATS(t)
	defer cleanup()
	var calls atomic.Int32
	stubTenantProvisioning(t, func(string, string) error { calls.Add(1); return nil }, func(string) error { calls.Add(1); return nil })

	if err := RegisterTenantProvisioning(nc); err != nil {
		t.Fatalf("RegisterTenantProvisioning: %v", err)
	}
	all, _ := nc.SubscribeSync("internal.tenant.>")
	_ = nc.Flush()

	publishJSON(t, nc, controlplane.SubjectTenantProvision, controlplane.TenantProvisionRequest{JobID: "pj_x.evil", TenantID: "t_1"})
	publishJSON(t, nc, controlplane.SubjectTenantDeprovision, controlplane.TenantDeprovisionRequest{JobID: "", TenantID: "t_1"})
	if err := nc.Publish(controlplane.SubjectTenantProvision, []byte("{not json")); err != nil {
		t.Fatalf("publish: %v", err)
	}
	_ = nc.Flush()

	// Drain the three requests themselves; anything after them is a reply.
	for i := 0; i < 3; i++ {
		if _, err := all.NextMsg(time.Second); err != nil {
			t.Fatalf("expected request %d to be observed: %v", i, err)
		}
	}
	if msg, err := all.NextMsg(300 * time.Millisecond); err == nil {
		t.Fatalf("expected no result to be published, got %s: %s", msg.Subject, msg.Data)
	}
	if calls.Load() != 0 {
		t.Fatalf("expected pki not to be called, got %d calls", calls.Load())
	}
}

// TestTenantProvision_QueueGroupDeliversOnce registers the handlers on two
// connections (two farmer replicas) and checks a single request is
// processed exactly once.
func TestTenantProvision_QueueGroupDeliversOnce(t *testing.T) {
	nc, cleanup := startEmbeddedNATS(t)
	defer cleanup()
	replica, err := nats.Connect(nc.ConnectedUrl())
	if err != nil {
		t.Fatalf("connect second replica: %v", err)
	}
	defer replica.Close()

	var calls atomic.Int32
	stubTenantProvisioning(t, func(string, string) error { calls.Add(1); return nil }, nil)
	if err := RegisterTenantProvisioning(nc); err != nil {
		t.Fatalf("RegisterTenantProvisioning (replica 1): %v", err)
	}
	if err := RegisterTenantProvisioning(replica); err != nil {
		t.Fatalf("RegisterTenantProvisioning (replica 2): %v", err)
	}
	_ = replica.Flush()
	sub, _ := nc.SubscribeSync(controlplane.SubjectTenantProvisionedWildcard)

	publishJSON(t, nc, controlplane.SubjectTenantProvision, controlplane.TenantProvisionRequest{JobID: "pj_once", TenantID: "t_1"})
	nextResult(t, sub)
	if _, err := sub.NextMsg(300 * time.Millisecond); err == nil {
		t.Fatal("expected exactly one result for one request across two replicas")
	}
	if calls.Load() != 1 {
		t.Fatalf("ProvisionTenant called %d times, want 1", calls.Load())
	}
}
