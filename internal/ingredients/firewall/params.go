//go:build linux

package firewall

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	nft "github.com/google/nftables"
	"golang.org/x/sys/unix"
)

// --- generic property accessors -------------------------------------------------

func paramString(params map[string]interface{}, key string) (string, bool) {
	v, ok := params[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

func paramStringOr(params map[string]interface{}, key, def string) string {
	s, ok := paramString(params, key)
	if !ok || s == "" {
		return def
	}
	return s
}

func requireString(params map[string]interface{}, key string) (string, error) {
	s, ok := paramString(params, key)
	if !ok || s == "" {
		return "", fmt.Errorf("%w: %s", ErrMissingProperty, key)
	}
	return s, nil
}

func paramBool(params map[string]interface{}, key string, def bool) bool {
	v, ok := params[key]
	if !ok {
		return def
	}
	switch b := v.(type) {
	case bool:
		return b
	case string:
		parsed, err := strconv.ParseBool(b)
		if err != nil {
			return def
		}
		return parsed
	default:
		return def
	}
}

// --- domain-specific parsing -----------------------------------------------------

// parseFamily maps a recipe's "family" property to the nftables address
// family. "inet" (the dual-stack IPv4+IPv6 family) is the default, matching
// modern `nft` tooling's own default table family.
func parseFamily(s string) (nft.TableFamily, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "inet":
		return nft.TableFamilyINet, nil
	case "ip", "ipv4":
		return nft.TableFamilyIPv4, nil
	case "ip6", "ipv6":
		return nft.TableFamilyIPv6, nil
	case "arp":
		return nft.TableFamilyARP, nil
	case "bridge":
		return nft.TableFamilyBridge, nil
	case "netdev":
		return nft.TableFamilyNetdev, nil
	default:
		return 0, fmt.Errorf("%w: unknown family %q", ErrInvalidProperty, s)
	}
}

func familyName(f nft.TableFamily) string {
	switch f {
	case nft.TableFamilyINet:
		return "inet"
	case nft.TableFamilyIPv4:
		return "ip"
	case nft.TableFamilyIPv6:
		return "ip6"
	case nft.TableFamilyARP:
		return "arp"
	case nft.TableFamilyBridge:
		return "bridge"
	case nft.TableFamilyNetdev:
		return "netdev"
	default:
		return "unspecified"
	}
}

// parseHook maps a recipe's "hook" property to the netfilter hook point. A
// non-empty hook makes the chain a base chain (one packets actually enter
// from the network stack); an empty hook makes it a regular chain only
// reachable via jump/goto from another chain.
func parseHook(s string) (*nft.ChainHook, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "":
		return nil, nil
	case "prerouting":
		return nft.ChainHookPrerouting, nil
	case "input":
		return nft.ChainHookInput, nil
	case "forward":
		return nft.ChainHookForward, nil
	case "output":
		return nft.ChainHookOutput, nil
	case "postrouting":
		return nft.ChainHookPostrouting, nil
	case "ingress":
		return nft.ChainHookIngress, nil
	case "egress":
		return nft.ChainHookEgress, nil
	default:
		return nil, fmt.Errorf("%w: unknown hook %q", ErrInvalidProperty, s)
	}
}

func parseChainType(s string) (nft.ChainType, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "filter":
		return nft.ChainTypeFilter, nil
	case "nat":
		return nft.ChainTypeNAT, nil
	case "route":
		return nft.ChainTypeRoute, nil
	default:
		return "", fmt.Errorf("%w: unknown chain type %q", ErrInvalidProperty, s)
	}
}

func parseChainPolicy(s string) (*nft.ChainPolicy, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "":
		return nil, nil
	case "accept":
		p := nft.ChainPolicyAccept
		return &p, nil
	case "drop":
		p := nft.ChainPolicyDrop
		return &p, nil
	default:
		return nil, fmt.Errorf("%w: unknown chain policy %q", ErrInvalidProperty, s)
	}
}

func parsePriority(s string) (int32, error) {
	if strings.TrimSpace(s) == "" {
		return 0, nil
	}
	p, err := strconv.ParseInt(s, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%w: invalid priority %q", ErrInvalidProperty, s)
	}
	return int32(p), nil
}

// parseProtocol maps a recipe's "protocol" property to an IPPROTO_* value
// used both for the l4proto match and to decide the transport header
// layout for sport/dport matches.
func parseProtocol(s string) (byte, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "tcp":
		return unix.IPPROTO_TCP, nil
	case "udp":
		return unix.IPPROTO_UDP, nil
	case "icmp":
		return unix.IPPROTO_ICMP, nil
	case "icmpv6", "icmp6":
		return unix.IPPROTO_ICMPV6, nil
	default:
		return 0, fmt.Errorf("%w: unknown protocol %q", ErrInvalidProperty, s)
	}
}

// addrMatch is a parsed saddr/daddr value ready to translate into a
// Payload(+Bitwise)+Cmp expression triplet.
type addrMatch struct {
	v6      bool
	network []byte // address to compare against (already masked, for a CIDR)
	mask    []byte // all-0xff when addr is a bare IP, not a CIDR
}

func fullMask(n int) []byte {
	m := make([]byte, n)
	for i := range m {
		m[i] = 0xff
	}
	return m
}

func isFullMask(m []byte) bool {
	for _, b := range m {
		if b != 0xff {
			return false
		}
	}
	return true
}

// parseAddr accepts either a bare IP ("10.0.0.1") or a CIDR
// ("10.0.0.0/24"); either IPv4 or IPv6.
func parseAddr(s string) (addrMatch, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		ip, ipnet, err := net.ParseCIDR(s)
		if err != nil {
			return addrMatch{}, fmt.Errorf("%w: invalid CIDR %q: %v", ErrInvalidProperty, s, err)
		}
		v6 := ip.To4() == nil
		if v6 {
			return addrMatch{v6: true, network: ipnet.IP.To16(), mask: fullMaskFrom(ipnet.Mask, 16)}, nil
		}
		return addrMatch{v6: false, network: ipnet.IP.To4(), mask: fullMaskFrom(ipnet.Mask, 4)}, nil
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return addrMatch{}, fmt.Errorf("%w: invalid address %q", ErrInvalidProperty, s)
	}
	if v4 := ip.To4(); v4 != nil {
		return addrMatch{v6: false, network: v4, mask: fullMask(4)}, nil
	}
	return addrMatch{v6: true, network: ip.To16(), mask: fullMask(16)}, nil
}

// fullMaskFrom normalizes a net.IPMask to exactly n bytes (net.ParseCIDR
// already returns a mask of the right length for the parsed family, this
// is just a defensive copy/guard).
func fullMaskFrom(m net.IPMask, n int) []byte {
	if len(m) == n {
		out := make([]byte, n)
		copy(out, m)
		return out
	}
	return fullMask(n)
}

// portMatch is a parsed sport/dport value: either a single port (lo == hi)
// or an inclusive range.
type portMatch struct {
	lo, hi uint16
}

func (p portMatch) isRange() bool { return p.lo != p.hi }

// parsePort accepts a single port ("443") or an inclusive range
// ("1024-65535" or "1024:65535").
func parsePort(s string) (portMatch, error) {
	s = strings.TrimSpace(s)
	sep := strings.IndexAny(s, "-:")
	if sep < 0 {
		p, err := strconv.ParseUint(s, 10, 16)
		if err != nil {
			return portMatch{}, fmt.Errorf("%w: invalid port %q", ErrInvalidProperty, s)
		}
		return portMatch{lo: uint16(p), hi: uint16(p)}, nil
	}
	lo, err := strconv.ParseUint(s[:sep], 10, 16)
	if err != nil {
		return portMatch{}, fmt.Errorf("%w: invalid port range %q", ErrInvalidProperty, s)
	}
	hi, err := strconv.ParseUint(s[sep+1:], 10, 16)
	if err != nil {
		return portMatch{}, fmt.Errorf("%w: invalid port range %q", ErrInvalidProperty, s)
	}
	if lo > hi {
		return portMatch{}, fmt.Errorf("%w: port range %q has lo > hi", ErrInvalidProperty, s)
	}
	return portMatch{lo: uint16(lo), hi: uint16(hi)}, nil
}
