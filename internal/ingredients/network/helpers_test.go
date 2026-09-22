//go:build linux

package network

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

var errConnFailed = fmt.Errorf("simulated connectivity failure")

// fakeLink is a minimal netlink.Link for tests, avoiding any dependency on
// real interfaces.
type fakeLink struct {
	attrs netlink.LinkAttrs
}

func (f *fakeLink) Attrs() *netlink.LinkAttrs { return &f.attrs }
func (f *fakeLink) Type() string              { return "fake" }

func newFakeLink(index int, name string, up bool, mtu int) *fakeLink {
	flags := net.Flags(0)
	if up {
		flags |= net.FlagUp
	}
	return &fakeLink{attrs: netlink.LinkAttrs{Index: index, Name: name, Flags: flags, MTU: mtu}}
}

// withMockLinkByName serves links from the given map, keyed by name.
func withMockLinkByName(t *testing.T, links map[string]*fakeLink) {
	t.Helper()
	orig := linkByName
	linkByName = func(name string) (netlink.Link, error) {
		if l, ok := links[name]; ok {
			return l, nil
		}
		return nil, fmt.Errorf("link not found: %s", name)
	}
	t.Cleanup(func() { linkByName = orig })
}

type linkStateCall struct {
	index int
	up    bool
}

func withMockLinkSetUpDown(t *testing.T) *[]linkStateCall {
	t.Helper()
	var calls []linkStateCall
	origUp, origDown := linkSetUp, linkSetDown
	linkSetUp = func(l netlink.Link) error {
		calls = append(calls, linkStateCall{index: l.Attrs().Index, up: true})
		return nil
	}
	linkSetDown = func(l netlink.Link) error {
		calls = append(calls, linkStateCall{index: l.Attrs().Index, up: false})
		return nil
	}
	t.Cleanup(func() { linkSetUp, linkSetDown = origUp, origDown })
	return &calls
}

type mtuCall struct {
	index, mtu int
}

func withMockLinkSetMTU(t *testing.T) *[]mtuCall {
	t.Helper()
	var calls []mtuCall
	orig := linkSetMTU
	linkSetMTU = func(l netlink.Link, mtu int) error {
		calls = append(calls, mtuCall{index: l.Attrs().Index, mtu: mtu})
		return nil
	}
	t.Cleanup(func() { linkSetMTU = orig })
	return &calls
}

func withMockAddrList(t *testing.T, addrs []netlink.Addr) {
	t.Helper()
	orig := addrList
	addrList = func(l netlink.Link, family int) ([]netlink.Addr, error) {
		return addrs, nil
	}
	t.Cleanup(func() { addrList = orig })
}

func withMockAddrAddDel(t *testing.T) (adds *[]string, dels *[]string) {
	t.Helper()
	var addCalls, delCalls []string
	origAdd, origDel := addrAdd, addrDel
	addrAdd = func(l netlink.Link, a *netlink.Addr) error {
		addCalls = append(addCalls, a.IPNet.String())
		return nil
	}
	addrDel = func(l netlink.Link, a *netlink.Addr) error {
		delCalls = append(delCalls, a.IPNet.String())
		return nil
	}
	t.Cleanup(func() { addrAdd, addrDel = origAdd, origDel })
	return &addCalls, &delCalls
}

func withMockRouteList(t *testing.T, routes []netlink.Route) {
	t.Helper()
	orig := routeList
	routeList = func(l netlink.Link, family int) ([]netlink.Route, error) {
		return routes, nil
	}
	t.Cleanup(func() { routeList = orig })
}

func withMockRouteAddDel(t *testing.T) (adds *[]netlink.Route, dels *[]netlink.Route) {
	t.Helper()
	var addCalls, delCalls []netlink.Route
	origAdd, origDel := routeAdd, routeDel
	routeAdd = func(r *netlink.Route) error {
		addCalls = append(addCalls, *r)
		return nil
	}
	routeDel = func(r *netlink.Route) error {
		delCalls = append(delCalls, *r)
		return nil
	}
	t.Cleanup(func() { routeAdd, routeDel = origAdd, origDel })
	return &addCalls, &delCalls
}

// withMockConnectivity replaces the guard's probe outright, bypassing
// TCP/RouteGet entirely, and reports how many times it was called.
func withMockConnectivity(t *testing.T, err error) *int {
	t.Helper()
	calls := 0
	orig := checkConnectivity
	checkConnectivity = func(target string, timeout time.Duration) error {
		calls++
		return err
	}
	t.Cleanup(func() { checkConnectivity = orig })
	return &calls
}
