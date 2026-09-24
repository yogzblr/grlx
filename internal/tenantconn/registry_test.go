package tenantconn

import (
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

// startTestNATS runs an embedded NATS server and returns a connection to it,
// matching internal/facts' test setup.
func startTestNATS(t *testing.T) (*server.Server, *nats.Conn) {
	t.Helper()
	ns, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1})
	if err != nil {
		t.Fatalf("start test NATS server: %v", err)
	}
	go ns.Start()
	if !ns.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS server failed to become ready")
	}
	t.Cleanup(ns.Shutdown)
	return ns, dial(t, ns)
}

func dial(t *testing.T, ns *server.Server) *nats.Conn {
	t.Helper()
	nc, err := nats.Connect(ns.ClientURL())
	if err != nil {
		t.Fatalf("connect to test NATS: %v", err)
	}
	t.Cleanup(nc.Close)
	return nc
}

func assertCounts(t *testing.T, r *Registry, wantConnected, wantTotal int) {
	t.Helper()
	connected, total := r.Counts()
	if connected != wantConnected || total != wantTotal {
		t.Errorf("Counts() = (%d, %d), want (%d, %d)", connected, total, wantConnected, wantTotal)
	}
}

func TestCountsEmpty(t *testing.T) {
	assertCounts(t, NewRegistry(), 0, 0)
}

// A tenant stuck retrying its first connect has no *nats.Conn, but must
// still count toward the total — otherwise it would be invisible.
func TestPendingCountsTowardTotalOnly(t *testing.T) {
	_, nc := startTestNATS(t)
	r := NewRegistry()
	r.Set("legacy", nc)
	r.MarkPending("tenant-b")
	assertCounts(t, r, 1, 2)
	if got := len(r.All()); got != 1 {
		t.Errorf("All() returned %d connections, want 1 (pending tenants have none)", got)
	}
}

func TestSetClearsPending(t *testing.T) {
	ns, nc := startTestNATS(t)
	r := NewRegistry()
	r.Set("legacy", nc)
	r.MarkPending("tenant-b")
	r.Set("tenant-b", dial(t, ns))
	assertCounts(t, r, 2, 2)
}

func TestMarkPendingKeepsRegisteredConn(t *testing.T) {
	_, nc := startTestNATS(t)
	r := NewRegistry()
	r.Set("tenant-a", nc)
	r.MarkPending("tenant-a")
	assertCounts(t, r, 1, 1)
}

// A registered connection that has dropped (here: closed, as it would be
// after nats.go exhausts its reconnect budget) still counts toward the
// total but not as connected.
func TestDisconnectedConnNotCountedAsConnected(t *testing.T) {
	ns, nc := startTestNATS(t)
	r := NewRegistry()
	r.Set("legacy", nc)
	down := dial(t, ns)
	r.Set("tenant-b", down)
	down.Close()
	assertCounts(t, r, 1, 2)
}

func TestRemove(t *testing.T) {
	_, nc := startTestNATS(t)
	r := NewRegistry()
	r.Set("tenant-a", nc)
	r.MarkPending("tenant-b")

	if got := r.Remove("tenant-a"); got != nc {
		t.Errorf("Remove(tenant-a) = %p, want %p", got, nc)
	}
	if got := r.Remove("tenant-b"); got != nil {
		t.Errorf("Remove(pending tenant-b) = %p, want nil", got)
	}
	if got := r.Remove("missing"); got != nil {
		t.Errorf("Remove(missing) = %p, want nil", got)
	}
	assertCounts(t, r, 0, 0)
}
