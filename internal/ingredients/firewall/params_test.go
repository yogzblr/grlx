//go:build linux

package firewall

import (
	"bytes"
	"errors"
	"testing"

	nft "github.com/google/nftables"
)

func TestParseFamily(t *testing.T) {
	cases := map[string]nft.TableFamily{
		"":       nft.TableFamilyINet,
		"inet":   nft.TableFamilyINet,
		"ip":     nft.TableFamilyIPv4,
		"ipv4":   nft.TableFamilyIPv4,
		"ip6":    nft.TableFamilyIPv6,
		"IPv6":   nft.TableFamilyIPv6,
		"arp":    nft.TableFamilyARP,
		"bridge": nft.TableFamilyBridge,
		"netdev": nft.TableFamilyNetdev,
	}
	for in, want := range cases {
		got, err := parseFamily(in)
		if err != nil {
			t.Fatalf("parseFamily(%q): unexpected error: %v", in, err)
		}
		if got != want {
			t.Errorf("parseFamily(%q) = %v, want %v", in, got, want)
		}
	}
	if _, err := parseFamily("bogus"); !errors.Is(err, ErrInvalidProperty) {
		t.Errorf("parseFamily(bogus): want ErrInvalidProperty, got %v", err)
	}
}

func TestParseHook(t *testing.T) {
	h, err := parseHook("")
	if err != nil || h != nil {
		t.Fatalf("parseHook(\"\") = %v, %v; want nil, nil", h, err)
	}
	h, err = parseHook("input")
	if err != nil {
		t.Fatalf("parseHook(input): %v", err)
	}
	if h != nft.ChainHookInput {
		t.Errorf("parseHook(input) = %v, want ChainHookInput", h)
	}
	if _, err := parseHook("sideways"); !errors.Is(err, ErrInvalidProperty) {
		t.Errorf("parseHook(sideways): want ErrInvalidProperty, got %v", err)
	}
}

func TestParseChainPolicyRequiresHook(t *testing.T) {
	_, err := parseChainSpec(map[string]interface{}{
		"name": "in", "table": "filter", "policy": "drop",
	})
	if !errors.Is(err, ErrInvalidProperty) {
		t.Fatalf("policy without hook: want ErrInvalidProperty, got %v", err)
	}
}

func TestParseProtocol(t *testing.T) {
	if _, err := parseProtocol("nope"); !errors.Is(err, ErrInvalidProperty) {
		t.Errorf("parseProtocol(nope): want ErrInvalidProperty, got %v", err)
	}
	p, err := parseProtocol("TCP")
	if err != nil {
		t.Fatalf("parseProtocol(TCP): %v", err)
	}
	if p != 6 {
		t.Errorf("parseProtocol(TCP) = %d, want 6", p)
	}
}

func TestParseAddrExactV4(t *testing.T) {
	a, err := parseAddr("10.0.0.5")
	if err != nil {
		t.Fatalf("parseAddr: %v", err)
	}
	if a.v6 {
		t.Fatal("expected v4")
	}
	if !bytes.Equal(a.network, []byte{10, 0, 0, 5}) {
		t.Errorf("network = %v", a.network)
	}
	if !isFullMask(a.mask) {
		t.Errorf("expected full mask for bare IP, got %v", a.mask)
	}
}

func TestParseAddrCIDRV4(t *testing.T) {
	a, err := parseAddr("10.1.2.0/24")
	if err != nil {
		t.Fatalf("parseAddr: %v", err)
	}
	if !bytes.Equal(a.network, []byte{10, 1, 2, 0}) {
		t.Errorf("network = %v", a.network)
	}
	if !bytes.Equal(a.mask, []byte{0xff, 0xff, 0xff, 0}) {
		t.Errorf("mask = %v", a.mask)
	}
	if isFullMask(a.mask) {
		t.Errorf("a /24 should not be a full mask")
	}
}

func TestParseAddrV6(t *testing.T) {
	a, err := parseAddr("2001:db8::1")
	if err != nil {
		t.Fatalf("parseAddr: %v", err)
	}
	if !a.v6 {
		t.Fatal("expected v6")
	}
	if len(a.network) != 16 || len(a.mask) != 16 {
		t.Errorf("expected 16-byte network/mask, got %d/%d", len(a.network), len(a.mask))
	}
}

func TestParseAddrInvalid(t *testing.T) {
	if _, err := parseAddr("not-an-ip"); !errors.Is(err, ErrInvalidProperty) {
		t.Errorf("parseAddr(not-an-ip): want ErrInvalidProperty, got %v", err)
	}
	if _, err := parseAddr("10.0.0.0/abc"); !errors.Is(err, ErrInvalidProperty) {
		t.Errorf("parseAddr(bad CIDR): want ErrInvalidProperty, got %v", err)
	}
}

func TestParsePort(t *testing.T) {
	p, err := parsePort("443")
	if err != nil {
		t.Fatalf("parsePort(443): %v", err)
	}
	if p.lo != 443 || p.hi != 443 || p.isRange() {
		t.Errorf("parsePort(443) = %+v", p)
	}

	p, err = parsePort("1024-2048")
	if err != nil {
		t.Fatalf("parsePort(range): %v", err)
	}
	if p.lo != 1024 || p.hi != 2048 || !p.isRange() {
		t.Errorf("parsePort(1024-2048) = %+v", p)
	}

	if _, err := parsePort("2048-1024"); !errors.Is(err, ErrInvalidProperty) {
		t.Errorf("parsePort(lo>hi): want ErrInvalidProperty, got %v", err)
	}
	if _, err := parsePort("notaport"); !errors.Is(err, ErrInvalidProperty) {
		t.Errorf("parsePort(notaport): want ErrInvalidProperty, got %v", err)
	}
}
