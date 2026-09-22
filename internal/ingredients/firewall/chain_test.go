//go:build linux

package firewall

import (
	"testing"

	nft "github.com/google/nftables"
)

func TestChainPresentBaseChain(t *testing.T) {
	conn := newFakeConn()
	spec, err := parseChainSpec(map[string]interface{}{
		"name": "input", "table": "filter", "family": "inet",
		"hook": "input", "type": "filter", "priority": "0", "policy": "drop",
	})
	if err != nil {
		t.Fatalf("parseChainSpec: %v", err)
	}

	res, err := chainPresent(conn, spec, false)
	if err != nil || !res.Succeeded || !res.Changed {
		t.Fatalf("apply: res=%+v err=%v", res, err)
	}
	if len(conn.chains) != 1 {
		t.Fatalf("expected 1 chain, got %d", len(conn.chains))
	}
	got := conn.chains[0]
	if got.Hooknum != nft.ChainHookInput {
		t.Errorf("Hooknum = %v, want ChainHookInput", got.Hooknum)
	}
	if got.Policy == nil || *got.Policy != nft.ChainPolicyDrop {
		t.Errorf("Policy = %v, want drop", got.Policy)
	}

	res, err = chainPresent(conn, spec, false)
	if err != nil || res.Changed {
		t.Fatalf("second apply should be a no-op: res=%+v err=%v", res, err)
	}
}

func TestChainPresentRegularChainHasNoHook(t *testing.T) {
	conn := newFakeConn()
	spec, err := parseChainSpec(map[string]interface{}{"name": "log-and-drop", "table": "filter"})
	if err != nil {
		t.Fatalf("parseChainSpec: %v", err)
	}
	if spec.isBase() {
		t.Fatal("chain with no hook should not be a base chain")
	}

	if _, err := chainPresent(conn, spec, false); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if conn.chains[0].Hooknum != nil || conn.chains[0].Policy != nil {
		t.Errorf("regular chain must not carry hook/policy: %+v", conn.chains[0])
	}
}

func TestChainAbsent(t *testing.T) {
	conn := newFakeConn()
	table := &nft.Table{Name: "filter", Family: nft.TableFamilyINet}
	conn.AddChain(&nft.Chain{Name: "input", Table: table})

	spec, err := parseChainSpec(map[string]interface{}{"name": "input", "table": "filter"})
	if err != nil {
		t.Fatalf("parseChainSpec: %v", err)
	}
	res, err := chainAbsent(conn, spec, false)
	if err != nil || !res.Changed {
		t.Fatalf("apply: res=%+v err=%v", res, err)
	}
	if len(conn.chains) != 0 {
		t.Fatalf("expected chain removed, got %d", len(conn.chains))
	}
}
