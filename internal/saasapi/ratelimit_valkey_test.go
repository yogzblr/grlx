package saasapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/valkey-io/valkey-go"
	"golang.org/x/time/rate"
)

// sharedLimiterBackend is a Valkey the shared-limiter tests run against,
// plus a way to move its clock forward.
type sharedLimiterBackend struct {
	client  valkey.Client
	advance func(time.Duration)
	// ttl returns key's remaining time to live.
	ttl func(key string) time.Duration
}

// newMiniredisBackend is an in-process Valkey stand-in (miniredis runs
// the Lua script for real) with a fake clock: advance moves the time
// TIME reports, so refill is tested without sleeping.
func newMiniredisBackend(t *testing.T) (*sharedLimiterBackend, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	now := time.Now()
	mr.SetTime(now)

	client := newTestValkeyClient(t, mr.Addr())
	return &sharedLimiterBackend{
		client: client,
		advance: func(d time.Duration) {
			now = now.Add(d)
			mr.SetTime(now)
		},
		ttl: func(key string) time.Duration { return mr.TTL(key) },
	}, mr
}

func newTestValkeyClient(t *testing.T, addr string) valkey.Client {
	t.Helper()
	client, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{addr}, DisableCache: true})
	if err != nil {
		t.Fatalf("connecting to test Valkey at %s: %v", addr, err)
	}
	t.Cleanup(client.Close)
	return client
}

// sharedLimiterContract is what any Valkey the limiter runs against must
// satisfy. It runs against miniredis always, and against a real server
// when SAASAPI_TEST_VALKEY_ADDR is set (TestValkeyLimiterRealServer).
func sharedLimiterContract(t *testing.T, newBackend func(t *testing.T) *sharedLimiterBackend) {
	ctx := context.Background()

	t.Run("burst then deny, shared across pods", func(t *testing.T) {
		b := newBackend(t)
		// Two limiter instances standing in for two saasapi pods: they
		// share nothing but Valkey.
		podA := NewValkeyLimiter(b.client, t.Name(), rate.Limit(1), 3)
		podB := NewValkeyLimiter(b.client, t.Name(), rate.Limit(1), 3)

		for i, pod := range []*valkeyLimiter{podA, podB, podA} {
			if !pod.allow(ctx, "t_a") {
				t.Fatalf("request %d within the burst of 3 should be allowed", i)
			}
		}
		if podB.allow(ctx, "t_a") {
			t.Fatalf("4th request should be denied: the burst is shared across pods, not 3 per pod")
		}
		if podA.allow(ctx, "t_a") {
			t.Fatalf("5th request should be denied on the other pod too")
		}
	})

	t.Run("refills after the window", func(t *testing.T) {
		b := newBackend(t)
		l := NewValkeyLimiter(b.client, t.Name(), rate.Limit(20), 1) // one per 50ms

		if !l.allow(ctx, "t_a") {
			t.Fatalf("first request should be allowed")
		}
		if l.allow(ctx, "t_a") {
			t.Fatalf("immediate second request should be denied")
		}
		b.advance(60 * time.Millisecond)
		if !l.allow(ctx, "t_a") {
			t.Fatalf("request after the refill window should be allowed")
		}
	})

	t.Run("tenants are independent", func(t *testing.T) {
		b := newBackend(t)
		l := NewValkeyLimiter(b.client, t.Name(), rate.Limit(1), 1)

		if !l.allow(ctx, "t_a") || !l.allow(ctx, "t_b") {
			t.Fatalf("each tenant's first request should be allowed")
		}
		if l.allow(ctx, "t_a") {
			t.Fatalf("t_a should still be limited by its own bucket")
		}
	})

	t.Run("key expires once the bucket would be full", func(t *testing.T) {
		b := newBackend(t)
		l := NewValkeyLimiter(b.client, "ttl-check", rate.Limit(1), 5)

		l.allow(ctx, "t_a")
		key := valkeyLimiterKeyPrefix + "ttl-check:t_a"
		ttl := b.ttl(key)
		// One request against a 1/s limit leaves the bucket one token
		// short, so it's full again in about a second.
		if ttl <= 0 || ttl > time.Second {
			t.Fatalf("TTL of %s = %v, want in (0, 1s]", key, ttl)
		}
	})

	t.Run("concurrent requests never exceed the burst", func(t *testing.T) {
		b := newBackend(t)
		const burst = 5
		pods := []*valkeyLimiter{
			NewValkeyLimiter(b.client, t.Name(), rate.Limit(0.001), burst),
			NewValkeyLimiter(b.client, t.Name(), rate.Limit(0.001), burst),
			NewValkeyLimiter(b.client, t.Name(), rate.Limit(0.001), burst),
		}

		var allowed atomic.Int64
		var wg sync.WaitGroup
		for i := 0; i < 60; i++ {
			wg.Add(1)
			go func(pod *valkeyLimiter) {
				defer wg.Done()
				if pod.allow(ctx, "t_a") {
					allowed.Add(1)
				}
			}(pods[i%len(pods)])
		}
		wg.Wait()
		if got := allowed.Load(); got != burst {
			t.Fatalf("allowed %d of 60 concurrent requests across 3 pods, want exactly the burst (%d)", got, burst)
		}
	})
}

func TestValkeyLimiter(t *testing.T) {
	sharedLimiterContract(t, func(t *testing.T) *sharedLimiterBackend {
		b, _ := newMiniredisBackend(t)
		return b
	})
}

// TestValkeyLimiterRealServer runs the same contract against a real
// Valkey (or Redis 7) server, e.g.:
//
//	SAASAPI_TEST_VALKEY_ADDR=127.0.0.1:6379 go test ./internal/saasapi/ -run RealServer
//
// It's opt-in because CI has no Valkey service. Each subtest flushes the
// database first, so point it at a throwaway server.
func TestValkeyLimiterRealServer(t *testing.T) {
	addr := os.Getenv("SAASAPI_TEST_VALKEY_ADDR")
	if addr == "" {
		t.Skip("SAASAPI_TEST_VALKEY_ADDR not set")
	}
	sharedLimiterContract(t, func(t *testing.T) *sharedLimiterBackend {
		client := newTestValkeyClient(t, addr)
		ctx := context.Background()
		if err := client.Do(ctx, client.B().Flushdb().Build()).Error(); err != nil {
			t.Fatalf("FLUSHDB: %v", err)
		}
		return &sharedLimiterBackend{
			client:  client,
			advance: time.Sleep, // a real server's clock can't be faked
			ttl: func(key string) time.Duration {
				ms, err := client.Do(ctx, client.B().Pttl().Key(key).Build()).AsInt64()
				if err != nil {
					t.Fatalf("PTTL %s: %v", key, err)
				}
				return time.Duration(ms) * time.Millisecond
			},
		}
	})
}

// TestValkeyLimiterFallsBackPerPodWhenValkeyIsDown: with Valkey gone, a
// pod neither fails every request nor drops the limit; it enforces the
// same rate and burst on its own.
func TestValkeyLimiterFallsBackPerPodWhenValkeyIsDown(t *testing.T) {
	b, mr := newMiniredisBackend(t)
	l := NewValkeyLimiter(b.client, t.Name(), rate.Limit(0.001), 2)
	ctx := context.Background()

	mr.Close()

	for i := 0; i < 2; i++ {
		if !l.allow(ctx, "t_a") {
			t.Fatalf("request %d within the burst should be allowed by the per-pod fallback", i)
		}
	}
	if l.allow(ctx, "t_a") {
		t.Fatalf("request beyond the burst should be denied by the per-pod fallback, not let through")
	}
}

// TestSetEnrollmentKeyRateLimitSharesLimitAcrossRouters is the
// end-to-end version: two routers built the way two saasapi pods build
// theirs (each with its own limiter instance) share one budget through
// Valkey, whereas without Valkey each gets the full burst.
func TestSetEnrollmentKeyRateLimitSharesLimitAcrossRouters(t *testing.T) {
	newTestDB(t)
	auth := newTestAuthEnv(t)
	tenantID := mustCreateTenant(t, "Acme Bank")
	b, _ := newMiniredisBackend(t)

	saved := enrollmentKeyIssuanceLimiter
	t.Cleanup(func() { enrollmentKeyIssuanceLimiter = saved })

	const burst = 4
	newPods := func(vc valkey.Client) []*http.ServeMux {
		var pods []*http.ServeMux
		for i := 0; i < 2; i++ {
			if err := SetEnrollmentKeyRateLimit(0.001, burst, vc); err != nil {
				t.Fatalf("SetEnrollmentKeyRateLimit: %v", err)
			}
			pods = append(pods, NewRouter())
		}
		return pods
	}
	countAllowed := func(pods []*http.ServeMux, tenant string) int {
		allowed := 0
		for i := 0; i < 3*burst; i++ {
			r := httptest.NewRequest("POST", "/v1/tenants/"+tenant+"/enrollment-keys",
				strings.NewReader(`{"expires_in_hours":24,"max_uses":50}`))
			auth.setAuthHeaders(r, tenant)
			w := httptest.NewRecorder()
			pods[i%len(pods)].ServeHTTP(w, r)
			switch w.Code {
			case http.StatusOK:
				allowed++
			case http.StatusTooManyRequests:
			default:
				t.Fatalf("unexpected status %d: %s", w.Code, w.Body.String())
			}
		}
		return allowed
	}

	if got := countAllowed(newPods(b.client), tenantID); got != burst {
		t.Fatalf("with Valkey, 2 pods allowed %d requests, want the shared burst %d", got, burst)
	}

	otherTenant := mustCreateTenant(t, "Other Tenant")
	if got := countAllowed(newPods(nil), otherTenant); got != 2*burst {
		t.Fatalf("without Valkey, 2 pods allowed %d requests, want %d (burst per pod)", got, 2*burst)
	}
}

func TestNewValkeyLimiterClampsInterval(t *testing.T) {
	for _, c := range []struct {
		r    rate.Limit
		want int64
	}{
		{1, 1000},
		{0.5, 2000},
		{20, 50},
		{5000, 1},                    // faster than 1/ms: clamped to 1ms
		{1e-20, 24 * 60 * 60 * 1000}, // slower than 1/day: clamped, no int64 overflow
	} {
		if got := NewValkeyLimiter(nil, "x", c.r, 1).intervalMS; got != c.want {
			t.Errorf("rate %v: intervalMS = %d, want %d", c.r, got, c.want)
		}
	}
}
