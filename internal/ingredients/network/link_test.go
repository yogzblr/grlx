//go:build linux

package network

import (
	"context"
	"testing"
)

func TestLinkApplyAlreadyUp(t *testing.T) {
	withMockLinkByName(t, map[string]*fakeLink{"eth0": newFakeLink(1, "eth0", true, 1500)})
	calls := withMockLinkSetUpDown(t)

	n := Network{id: "t", method: "link", params: map[string]interface{}{"name": "eth0", "state": "up"}}
	result, err := n.Apply(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Succeeded || result.Changed {
		t.Fatalf("unexpected result: %+v", result)
	}
	if len(*calls) != 0 {
		t.Fatalf("expected no state calls, got %v", *calls)
	}
}

func TestLinkApplyDownGuardPasses(t *testing.T) {
	withMockLinkByName(t, map[string]*fakeLink{"eth0": newFakeLink(1, "eth0", true, 1500)})
	stateCalls := withMockLinkSetUpDown(t)
	connCalls := withMockConnectivity(t, nil)
	withMockRouteList(t, nil) // no default gateway found

	n := Network{id: "t", method: "link", params: map[string]interface{}{"name": "eth0", "state": "down"}}
	result, err := n.Apply(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Succeeded || !result.Changed {
		t.Fatalf("unexpected result: %+v", result)
	}
	if len(*stateCalls) != 1 || (*stateCalls)[0].up {
		t.Fatalf("expected one down call, got %v", *stateCalls)
	}
	// No default gateway and no explicit connectivity_target -> guard skips
	// the check entirely (nothing to check against), so it's never invoked.
	if *connCalls != 0 {
		t.Fatalf("expected connectivity check to be skipped, got %d calls", *connCalls)
	}
}

func TestLinkApplyDownGuardFailsRollsBack(t *testing.T) {
	withMockLinkByName(t, map[string]*fakeLink{"eth0": newFakeLink(1, "eth0", true, 1500)})
	stateCalls := withMockLinkSetUpDown(t)
	withMockConnectivity(t, errConnFailed)

	n := Network{id: "t", method: "link", params: map[string]interface{}{
		"name": "eth0", "state": "down", "connectivity_target": "10.0.0.1",
	}}
	result, err := n.Apply(context.Background())
	if err == nil {
		t.Fatal("expected error when connectivity check fails")
	}
	if !result.Failed {
		t.Fatalf("expected Failed=true, got %+v", result)
	}
	if len(*stateCalls) != 2 {
		t.Fatalf("expected down then rollback-up, got %v", *stateCalls)
	}
	if (*stateCalls)[0].up || !(*stateCalls)[1].up {
		t.Fatalf("expected [down, up] sequence, got %v", *stateCalls)
	}
}

func TestLinkApplyDownGuardFailsNoRollback(t *testing.T) {
	withMockLinkByName(t, map[string]*fakeLink{"eth0": newFakeLink(1, "eth0", true, 1500)})
	stateCalls := withMockLinkSetUpDown(t)
	withMockConnectivity(t, errConnFailed)

	n := Network{id: "t", method: "link", params: map[string]interface{}{
		"name": "eth0", "state": "down", "connectivity_target": "10.0.0.1",
		"rollback_on_failure": false,
	}}
	result, err := n.Apply(context.Background())
	if err == nil {
		t.Fatal("expected error when connectivity check fails")
	}
	if !result.Failed {
		t.Fatalf("expected Failed=true, got %+v", result)
	}
	if len(*stateCalls) != 1 {
		t.Fatalf("expected no rollback call, got %v", *stateCalls)
	}
}

func TestLinkApplyMTUOnly(t *testing.T) {
	withMockLinkByName(t, map[string]*fakeLink{"eth0": newFakeLink(1, "eth0", true, 1500)})
	withMockConnectivity(t, nil)
	withMockRouteList(t, nil)
	mtuCalls := withMockLinkSetMTU(t)

	n := Network{id: "t", method: "link", params: map[string]interface{}{"name": "eth0", "state": "up", "mtu": 9000}}
	result, err := n.Apply(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Changed {
		t.Fatalf("expected change, got %+v", result)
	}
	if len(*mtuCalls) != 1 || (*mtuCalls)[0].mtu != 9000 {
		t.Fatalf("expected one mtu=9000 call, got %v", *mtuCalls)
	}
}

func TestLinkTestModeDoesNotMutate(t *testing.T) {
	withMockLinkByName(t, map[string]*fakeLink{"eth0": newFakeLink(1, "eth0", true, 1500)})
	stateCalls := withMockLinkSetUpDown(t)

	n := Network{id: "t", method: "link", params: map[string]interface{}{"name": "eth0", "state": "down"}}
	result, err := n.Test(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Succeeded || !result.Changed {
		t.Fatalf("unexpected result: %+v", result)
	}
	if len(*stateCalls) != 0 {
		t.Fatalf("test mode must not mutate, got %v", *stateCalls)
	}
}

func TestLinkInvalidState(t *testing.T) {
	n := Network{id: "t", method: "link", params: map[string]interface{}{"name": "eth0", "state": "sideways"}}
	result, err := n.Apply(context.Background())
	if err == nil {
		t.Fatal("expected error for invalid state")
	}
	if !result.Failed {
		t.Fatalf("expected Failed=true, got %+v", result)
	}
}

func TestLinkUnknownInterface(t *testing.T) {
	withMockLinkByName(t, map[string]*fakeLink{})

	n := Network{id: "t", method: "link", params: map[string]interface{}{"name": "eth99", "state": "up"}}
	result, err := n.Apply(context.Background())
	if err == nil {
		t.Fatal("expected error for unknown interface")
	}
	if !result.Failed {
		t.Fatalf("expected Failed=true, got %+v", result)
	}
}
