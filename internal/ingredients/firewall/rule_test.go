//go:build linux

package firewall

import (
	"errors"
	"reflect"
	"testing"

	nft "github.com/google/nftables"
)

func mustRuleSpec(t *testing.T, params map[string]interface{}) ruleSpec {
	t.Helper()
	spec, err := parseRuleSpec(params, true)
	if err != nil {
		t.Fatalf("parseRuleSpec: %v", err)
	}
	return spec
}

func TestParseRuleSpecPortsRequireProtocol(t *testing.T) {
	_, err := parseRuleSpec(map[string]interface{}{
		"name": "r1", "table": "filter", "chain": "input",
		"dport": "443", "action": "accept",
	}, true)
	if !errors.Is(err, ErrInvalidProperty) {
		t.Fatalf("dport without protocol: want ErrInvalidProperty, got %v", err)
	}
}

func TestParseRuleSpecPortsRejectIcmp(t *testing.T) {
	_, err := parseRuleSpec(map[string]interface{}{
		"name": "r1", "table": "filter", "chain": "input",
		"protocol": "icmp", "dport": "443", "action": "accept",
	}, true)
	if !errors.Is(err, ErrInvalidProperty) {
		t.Fatalf("dport with icmp: want ErrInvalidProperty, got %v", err)
	}
}

func TestParseRuleSpecInvalidAction(t *testing.T) {
	_, err := parseRuleSpec(map[string]interface{}{
		"name": "r1", "table": "filter", "chain": "input", "action": "yeet",
	}, true)
	if !errors.Is(err, ErrInvalidProperty) {
		t.Fatalf("bad action: want ErrInvalidProperty, got %v", err)
	}
}

func TestBuildExprsIsDeterministic(t *testing.T) {
	spec := mustRuleSpec(t, map[string]interface{}{
		"name": "allow-ssh", "table": "filter", "chain": "input",
		"protocol": "tcp", "dport": "22", "saddr": "10.0.0.0/24",
		"action": "accept", "counter": true,
	})
	e1, err := buildExprs(spec)
	if err != nil {
		t.Fatalf("buildExprs: %v", err)
	}
	e2, err := buildExprs(spec)
	if err != nil {
		t.Fatalf("buildExprs: %v", err)
	}
	if !reflect.DeepEqual(e1, e2) {
		t.Fatalf("buildExprs must be deterministic for the same spec:\n%+v\n%+v", e1, e2)
	}
}

func TestRulePresentAddsNoopsThenUpdatesOnDrift(t *testing.T) {
	conn := newFakeConn()
	table := &nft.Table{Name: "filter", Family: nft.TableFamilyINet}
	chain := &nft.Chain{Name: "input", Table: table}
	conn.AddTable(table)
	conn.AddChain(chain)

	spec := mustRuleSpec(t, map[string]interface{}{
		"name": "allow-ssh", "table": "filter", "chain": "input",
		"protocol": "tcp", "dport": "22", "action": "accept",
	})

	res, err := rulePresent(conn, spec, false)
	if err != nil || !res.Changed {
		t.Fatalf("first apply: res=%+v err=%v", res, err)
	}
	if got := len(conn.rules[ruleKey("filter", "input")]); got != 1 {
		t.Fatalf("expected 1 rule, got %d", got)
	}

	res, err = rulePresent(conn, spec, false)
	if err != nil || res.Changed {
		t.Fatalf("second apply should be a no-op: res=%+v err=%v", res, err)
	}
	if got := len(conn.rules[ruleKey("filter", "input")]); got != 1 {
		t.Fatalf("no-op apply must not duplicate the rule, got %d", got)
	}

	// Same name, different match -- must be detected as drift and replaced,
	// not left stale alongside the old rule.
	drifted := mustRuleSpec(t, map[string]interface{}{
		"name": "allow-ssh", "table": "filter", "chain": "input",
		"protocol": "tcp", "dport": "2222", "action": "accept",
	})
	res, err = rulePresent(conn, drifted, false)
	if err != nil || !res.Changed {
		t.Fatalf("drift apply: res=%+v err=%v", res, err)
	}
	rules := conn.rules[ruleKey("filter", "input")]
	if len(rules) != 1 {
		t.Fatalf("drift apply must replace, not duplicate: got %d rules", len(rules))
	}
	wantExprs, err := buildExprs(drifted)
	if err != nil {
		t.Fatalf("buildExprs: %v", err)
	}
	if !reflect.DeepEqual(rules[0].Exprs, wantExprs) {
		t.Fatalf("rule after drift apply does not match new spec:\n%+v\n%+v", rules[0].Exprs, wantExprs)
	}
}

func TestRulePresentDryRunDoesNotMutate(t *testing.T) {
	conn := newFakeConn()
	spec := mustRuleSpec(t, map[string]interface{}{
		"name": "allow-ssh", "table": "filter", "chain": "input",
		"protocol": "tcp", "dport": "22", "action": "accept",
	})
	res, err := rulePresent(conn, spec, true)
	if err != nil || !res.Changed {
		t.Fatalf("dry run: res=%+v err=%v", res, err)
	}
	if got := len(conn.rules[ruleKey("filter", "input")]); got != 0 {
		t.Fatalf("dry run must not mutate, got %d rules", got)
	}
}

func TestRuleAbsentRemovesByName(t *testing.T) {
	conn := newFakeConn()
	spec := mustRuleSpec(t, map[string]interface{}{
		"name": "allow-ssh", "table": "filter", "chain": "input",
		"protocol": "tcp", "dport": "22", "action": "accept",
	})
	if _, err := rulePresent(conn, spec, false); err != nil {
		t.Fatalf("seed rule: %v", err)
	}

	absentSpec, err := parseRuleSpec(map[string]interface{}{
		"name": "allow-ssh", "table": "filter", "chain": "input",
	}, false)
	if err != nil {
		t.Fatalf("parseRuleSpec absent: %v", err)
	}

	res, err := ruleAbsent(conn, absentSpec, false)
	if err != nil || !res.Changed {
		t.Fatalf("remove: res=%+v err=%v", res, err)
	}
	if got := len(conn.rules[ruleKey("filter", "input")]); got != 0 {
		t.Fatalf("expected rule removed, got %d", got)
	}

	res, err = ruleAbsent(conn, absentSpec, false)
	if err != nil || res.Changed {
		t.Fatalf("second removal should be a no-op: res=%+v err=%v", res, err)
	}
}

func TestRuleAbsentLeavesOtherNamedRulesAlone(t *testing.T) {
	conn := newFakeConn()
	specA := mustRuleSpec(t, map[string]interface{}{
		"name": "a", "table": "filter", "chain": "input", "action": "accept",
	})
	specB := mustRuleSpec(t, map[string]interface{}{
		"name": "b", "table": "filter", "chain": "input", "action": "drop",
	})
	if _, err := rulePresent(conn, specA, false); err != nil {
		t.Fatalf("seed a: %v", err)
	}
	if _, err := rulePresent(conn, specB, false); err != nil {
		t.Fatalf("seed b: %v", err)
	}

	absentA, err := parseRuleSpec(map[string]interface{}{
		"name": "a", "table": "filter", "chain": "input",
	}, false)
	if err != nil {
		t.Fatalf("parseRuleSpec: %v", err)
	}
	if _, err := ruleAbsent(conn, absentA, false); err != nil {
		t.Fatalf("remove a: %v", err)
	}

	rules := conn.rules[ruleKey("filter", "input")]
	if len(rules) != 1 {
		t.Fatalf("expected rule b to remain, got %d rules", len(rules))
	}
	if c, ok := ruleComment(rules[0]); !ok || c != "b" {
		t.Fatalf("remaining rule should be %q, got %q", "b", c)
	}
}

func TestRulePresentReject(t *testing.T) {
	spec := mustRuleSpec(t, map[string]interface{}{
		"name": "reject-all", "table": "filter", "chain": "input", "action": "reject",
	})
	exprs, err := buildExprs(spec)
	if err != nil {
		t.Fatalf("buildExprs: %v", err)
	}
	if len(exprs) == 0 {
		t.Fatal("expected at least the reject expr")
	}
}
