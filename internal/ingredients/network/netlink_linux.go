//go:build linux

package network

import "github.com/vishvananda/netlink"

// mainTable is the kernel's "main" routing table ID (unix.RT_TABLE_MAIN).
// netlink normalizes an unspecified (0) table to this value, so route
// matching treats the two as equivalent.
const mainTable = 254

// The following wrap the vishvananda/netlink package calls behind
// package-level vars, the same pattern the mount ingredient uses for its
// syscalls (see mount/syscall_linux.go): tests substitute fakes here so they
// can exercise every branch without CAP_NET_ADMIN or a real network
// namespace.
var (
	linkByName  = netlink.LinkByName
	linkSetUp   = netlink.LinkSetUp
	linkSetDown = netlink.LinkSetDown
	linkSetMTU  = netlink.LinkSetMTU
	addrList    = netlink.AddrList
	addrAdd     = netlink.AddrAdd
	addrDel     = netlink.AddrDel
	routeList   = netlink.RouteList
	routeAdd    = netlink.RouteAdd
	routeDel    = netlink.RouteDel
	routeGet    = netlink.RouteGet
)

// normalizeTable maps the "unspecified" table (0) onto mainTable so a route
// created without an explicit table (which the kernel files under main) can
// be matched against one a caller asked for by name, and vice versa.
func normalizeTable(t int) int {
	if t == 0 {
		return mainTable
	}
	return t
}
