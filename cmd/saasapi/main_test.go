package main

import (
	"context"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/valkey-io/valkey-go"

	"github.com/gogrlx/grlx/v2/internal/heartbeat"
)

// newOnlineSproutStore returns a miniredis holding the heartbeat key farmer's
// listener would write for tenantID/sproutID. internal/heartbeat's key
// format is unexported, so it's repeated here; the wired case below fails
// if it ever drifts.
func newOnlineSproutStore(t *testing.T, tenantID, sproutID string) *miniredis.Miniredis {
	t.Helper()
	mr := miniredis.RunT(t)
	if err := mr.Set("grlx:heartbeat:"+tenantID+":"+sproutID, "1"); err != nil {
		t.Fatalf("setting heartbeat key: %v", err)
	}
	return mr
}

func resetHeartbeatClient(t *testing.T) {
	t.Helper()
	heartbeat.SetClient(nil)
	t.Cleanup(func() { heartbeat.SetClient(nil) })
}

// TestInitHeartbeatClientWired: with a Valkey client (SAASAPI_VALKEY_ADDRS
// set), heartbeat.IsOnline reads live keys through it.
func TestInitHeartbeatClientWired(t *testing.T) {
	resetHeartbeatClient(t)
	mr := newOnlineSproutStore(t, "t_acme", "web-01")
	vc, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{mr.Addr()}, DisableCache: true})
	if err != nil {
		t.Fatalf("creating valkey client: %v", err)
	}
	t.Cleanup(vc.Close)

	initHeartbeatClient(vc)

	ctx := context.Background()
	if !heartbeat.IsOnline(ctx, "t_acme", "web-01") {
		t.Fatal("IsOnline = false for a sprout with a live heartbeat key; client not wired")
	}
	if heartbeat.IsOnline(ctx, "t_acme", "web-02") {
		t.Fatal("IsOnline = true for a sprout with no heartbeat key")
	}
	if heartbeat.IsOnline(ctx, "t_other", "web-01") {
		t.Fatal("IsOnline = true for another tenant's same-named sprout")
	}
}

// TestInitHeartbeatClientUnwired: with SAASAPI_VALKEY_ADDRS unset, main's vc
// is nil. initHeartbeatClient must not panic and must leave heartbeat
// unwired, so IsOnline degrades to false — even for a sprout that a
// reachable Valkey would report as online.
func TestInitHeartbeatClientUnwired(t *testing.T) {
	resetHeartbeatClient(t)
	newOnlineSproutStore(t, "t_acme", "web-01")

	initHeartbeatClient(nil)

	if heartbeat.IsOnline(context.Background(), "t_acme", "web-01") {
		t.Fatal("IsOnline = true with no Valkey client configured; want false (connected: false)")
	}
}
