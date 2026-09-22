//go:build linux

package network

import (
	"context"
	"testing"

	"github.com/vishvananda/netlink"
)

func mustAddr(t *testing.T, s string) netlink.Addr {
	t.Helper()
	a, err := netlink.ParseAddr(s)
	if err != nil {
		t.Fatalf("ParseAddr(%q): %v", s, err)
	}
	return *a
}

func TestAddressPresentAlreadyThere(t *testing.T) {
	withMockLinkByName(t, map[string]*fakeLink{"eth0": newFakeLink(1, "eth0", true, 1500)})
	withMockAddrList(t, []netlink.Addr{mustAddr(t, "10.0.0.5/24")})
	adds, _ := withMockAddrAddDel(t)

	n := Network{id: "t", method: "address_present", params: map[string]interface{}{"name": "eth0", "address": "10.0.0.5/24"}}
	result, err := n.Apply(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Succeeded || result.Changed {
		t.Fatalf("unexpected result: %+v", result)
	}
	if len(*adds) != 0 {
		t.Fatalf("expected no addrAdd calls, got %v", *adds)
	}
}

func TestAddressPresentAddsNewNoGuard(t *testing.T) {
	withMockLinkByName(t, map[string]*fakeLink{"eth0": newFakeLink(1, "eth0", true, 1500)})
	withMockAddrList(t, nil)
	adds, _ := withMockAddrAddDel(t)
	// Guard would fail if it ran; address_present must never invoke it since
	// adding an address is additive and can't remove reachability.
	connCalls := withMockConnectivity(t, errConnFailed)

	n := Network{id: "t", method: "address_present", params: map[string]interface{}{"name": "eth0", "address": "10.0.0.5/24"}}
	result, err := n.Apply(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Succeeded || !result.Changed {
		t.Fatalf("unexpected result: %+v", result)
	}
	if len(*adds) != 1 {
		t.Fatalf("expected one addrAdd call, got %v", *adds)
	}
	if *connCalls != 0 {
		t.Fatalf("expected connectivity guard not to run for address_present, got %d calls", *connCalls)
	}
}

func TestAddressAbsentAlreadyGone(t *testing.T) {
	withMockLinkByName(t, map[string]*fakeLink{"eth0": newFakeLink(1, "eth0", true, 1500)})
	withMockAddrList(t, nil)
	_, dels := withMockAddrAddDel(t)

	n := Network{id: "t", method: "address_absent", params: map[string]interface{}{"name": "eth0", "address": "10.0.0.5/24"}}
	result, err := n.Apply(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Succeeded || result.Changed {
		t.Fatalf("unexpected result: %+v", result)
	}
	if len(*dels) != 0 {
		t.Fatalf("expected no addrDel calls, got %v", *dels)
	}
}

func TestAddressAbsentGuardFailsRollsBack(t *testing.T) {
	withMockLinkByName(t, map[string]*fakeLink{"eth0": newFakeLink(1, "eth0", true, 1500)})
	withMockAddrList(t, []netlink.Addr{mustAddr(t, "10.0.0.5/24")})
	adds, dels := withMockAddrAddDel(t)
	withMockConnectivity(t, errConnFailed)

	n := Network{id: "t", method: "address_absent", params: map[string]interface{}{
		"name": "eth0", "address": "10.0.0.5/24", "connectivity_target": "10.0.0.1",
	}}
	result, err := n.Apply(context.Background())
	if err == nil {
		t.Fatal("expected error when connectivity check fails")
	}
	if !result.Failed {
		t.Fatalf("expected Failed=true, got %+v", result)
	}
	if len(*dels) != 1 {
		t.Fatalf("expected one addrDel call, got %v", *dels)
	}
	if len(*adds) != 1 {
		t.Fatalf("expected the address to be re-added on rollback, got %v", *adds)
	}
}

func TestAddressAbsentGuardPasses(t *testing.T) {
	withMockLinkByName(t, map[string]*fakeLink{"eth0": newFakeLink(1, "eth0", true, 1500)})
	withMockAddrList(t, []netlink.Addr{mustAddr(t, "10.0.0.5/24")})
	_, dels := withMockAddrAddDel(t)
	withMockConnectivity(t, nil)

	n := Network{id: "t", method: "address_absent", params: map[string]interface{}{
		"name": "eth0", "address": "10.0.0.5/24", "connectivity_target": "10.0.0.1",
	}}
	result, err := n.Apply(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Succeeded || !result.Changed {
		t.Fatalf("unexpected result: %+v", result)
	}
	if len(*dels) != 1 {
		t.Fatalf("expected one addrDel call, got %v", *dels)
	}
}
