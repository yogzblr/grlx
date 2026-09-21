//go:build linux

package network

import (
	"context"
	"net"
	"testing"

	"github.com/vishvananda/netlink"
)

func mustIPNet(t *testing.T, s string) *net.IPNet {
	t.Helper()
	n, err := netlink.ParseIPNet(s)
	if err != nil {
		t.Fatalf("ParseIPNet(%q): %v", s, err)
	}
	return n
}

func TestRoutePresentRequiresGatewayOrName(t *testing.T) {
	n := Network{id: "t", method: "route_present", params: map[string]interface{}{"destination": "default"}}
	result, err := n.Apply(context.Background())
	if err == nil {
		t.Fatal("expected error when neither gateway nor name is set")
	}
	if !result.Failed {
		t.Fatalf("expected Failed=true, got %+v", result)
	}
}

func TestRoutePresentAddsNewDefaultRoute(t *testing.T) {
	withMockRouteList(t, nil)
	adds, dels := withMockRouteAddDel(t)
	withMockConnectivity(t, nil)

	n := Network{id: "t", method: "route_present", params: map[string]interface{}{
		"destination": "default", "gateway": "192.168.1.1",
	}}
	result, err := n.Apply(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Succeeded || !result.Changed {
		t.Fatalf("unexpected result: %+v", result)
	}
	if len(*adds) != 1 || (*adds)[0].Dst != nil || !(*adds)[0].Gw.Equal(net.ParseIP("192.168.1.1")) {
		t.Fatalf("unexpected routeAdd calls: %v", *adds)
	}
	if len(*dels) != 0 {
		t.Fatalf("expected no routeDel calls, got %v", *dels)
	}
}

func TestRoutePresentAlreadyPresent(t *testing.T) {
	withMockRouteList(t, []netlink.Route{
		{Dst: nil, Gw: net.ParseIP("192.168.1.1"), Table: 254},
	})
	adds, _ := withMockRouteAddDel(t)

	n := Network{id: "t", method: "route_present", params: map[string]interface{}{
		"destination": "default", "gateway": "192.168.1.1",
	}}
	result, err := n.Apply(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Succeeded || result.Changed {
		t.Fatalf("unexpected result: %+v", result)
	}
	if len(*adds) != 0 {
		t.Fatalf("expected no changes, got %v", *adds)
	}
}

func TestRoutePresentUpdatesChangedGateway(t *testing.T) {
	withMockRouteList(t, []netlink.Route{
		{Dst: nil, Gw: net.ParseIP("192.168.1.1"), Table: 254},
	})
	adds, dels := withMockRouteAddDel(t)
	withMockConnectivity(t, nil)

	n := Network{id: "t", method: "route_present", params: map[string]interface{}{
		"destination": "default", "gateway": "192.168.1.254",
	}}
	result, err := n.Apply(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Changed {
		t.Fatalf("expected change, got %+v", result)
	}
	if len(*dels) != 1 || len(*adds) != 1 {
		t.Fatalf("expected one delete+add, got dels=%v adds=%v", *dels, *adds)
	}
	if !(*adds)[0].Gw.Equal(net.ParseIP("192.168.1.254")) {
		t.Fatalf("expected new gateway to be added, got %v", *adds)
	}
}

func TestRoutePresentGuardFailsRollsBackToPreviousRoute(t *testing.T) {
	oldRoute := netlink.Route{Dst: nil, Gw: net.ParseIP("192.168.1.1"), Table: 254}
	withMockRouteList(t, []netlink.Route{oldRoute})
	adds, dels := withMockRouteAddDel(t)
	withMockConnectivity(t, errConnFailed)

	n := Network{id: "t", method: "route_present", params: map[string]interface{}{
		"destination": "default", "gateway": "192.168.1.254", "connectivity_target": "8.8.8.8",
	}}
	result, err := n.Apply(context.Background())
	if err == nil {
		t.Fatal("expected error when connectivity check fails")
	}
	if !result.Failed {
		t.Fatalf("expected Failed=true, got %+v", result)
	}
	// apply: del old, add new. rollback: del new, add old.
	if len(*dels) != 2 || len(*adds) != 2 {
		t.Fatalf("expected 2 dels and 2 adds (apply + rollback), got dels=%v adds=%v", *dels, *adds)
	}
	if !(*adds)[1].Gw.Equal(net.ParseIP("192.168.1.1")) {
		t.Fatalf("expected rollback to restore the old gateway, got %v", *adds)
	}
}

func TestRouteAbsentAlreadyGone(t *testing.T) {
	withMockRouteList(t, nil)
	_, dels := withMockRouteAddDel(t)

	n := Network{id: "t", method: "route_absent", params: map[string]interface{}{"destination": "10.0.0.0/8"}}
	result, err := n.Apply(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Succeeded || result.Changed {
		t.Fatalf("unexpected result: %+v", result)
	}
	if len(*dels) != 0 {
		t.Fatalf("expected no deletes, got %v", *dels)
	}
}

func TestRouteAbsentRemovesMatching(t *testing.T) {
	dst := mustIPNet(t, "10.0.0.0/8")
	withMockRouteList(t, []netlink.Route{{Dst: dst, Gw: net.ParseIP("192.168.1.1"), Table: 254}})
	adds, dels := withMockRouteAddDel(t)
	withMockConnectivity(t, nil)

	n := Network{id: "t", method: "route_absent", params: map[string]interface{}{"destination": "10.0.0.0/8"}}
	result, err := n.Apply(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Succeeded || !result.Changed {
		t.Fatalf("unexpected result: %+v", result)
	}
	if len(*dels) != 1 {
		t.Fatalf("expected one delete, got %v", *dels)
	}
	if len(*adds) != 0 {
		t.Fatalf("expected no rollback add, got %v", *adds)
	}
}

func TestRouteAbsentGuardFailsRestoresRoute(t *testing.T) {
	dst := mustIPNet(t, "0.0.0.0/0")
	defaultRoute := netlink.Route{Dst: nil, Gw: net.ParseIP("192.168.1.1"), Table: 254}
	_ = dst
	withMockRouteList(t, []netlink.Route{defaultRoute})
	adds, dels := withMockRouteAddDel(t)
	withMockConnectivity(t, errConnFailed)

	n := Network{id: "t", method: "route_absent", params: map[string]interface{}{
		"destination": "default", "connectivity_target": "8.8.8.8",
	}}
	result, err := n.Apply(context.Background())
	if err == nil {
		t.Fatal("expected error: removing the default route should trip the guard")
	}
	if !result.Failed {
		t.Fatalf("expected Failed=true, got %+v", result)
	}
	if len(*dels) != 1 {
		t.Fatalf("expected one delete, got %v", *dels)
	}
	if len(*adds) != 1 || !(*adds)[0].Gw.Equal(net.ParseIP("192.168.1.1")) {
		t.Fatalf("expected the default route to be restored, got %v", *adds)
	}
}

func TestRouteAbsentTestModeDoesNotMutate(t *testing.T) {
	withMockRouteList(t, []netlink.Route{{Dst: nil, Gw: net.ParseIP("192.168.1.1"), Table: 254}})
	adds, dels := withMockRouteAddDel(t)

	n := Network{id: "t", method: "route_absent", params: map[string]interface{}{"destination": "default"}}
	result, err := n.Test(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Changed {
		t.Fatalf("expected changed=true in test mode, got %+v", result)
	}
	if len(*adds) != 0 || len(*dels) != 0 {
		t.Fatalf("test mode must not mutate, got adds=%v dels=%v", *adds, *dels)
	}
}
