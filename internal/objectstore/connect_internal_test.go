package objectstore

import (
	"testing"
	"time"
)

func TestBackoffDoublesAndCaps(t *testing.T) {
	p := RetryPolicy{InitialBackoff: time.Second, MaxBackoff: 30 * time.Second}
	want := []time.Duration{1, 2, 4, 8, 16, 30, 30, 30}
	for i, w := range want {
		if got := p.backoff(i + 1); got != w*time.Second {
			t.Errorf("backoff(%d) = %s, want %s", i+1, got, w*time.Second)
		}
	}
	// Large attempt counts must not overflow past the cap.
	if got := p.backoff(200); got != 30*time.Second {
		t.Errorf("backoff(200) = %s, want cap", got)
	}
}

func TestJitterStaysInUpperHalf(t *testing.T) {
	b := 8 * time.Second
	for range 1000 {
		if got := jitter(b); got < b/2 || got > b {
			t.Fatalf("jitter(%s) = %s, want within [%s, %s]", b, got, b/2, b)
		}
	}
}

func TestRetryPolicyDefaults(t *testing.T) {
	got := RetryPolicy{MaxAttempts: 3}.withDefaults()
	d := DefaultRetryPolicy()
	if got.MaxAttempts != 3 {
		t.Errorf("explicit MaxAttempts overridden: %d", got.MaxAttempts)
	}
	if got.InitialBackoff != d.InitialBackoff || got.MaxBackoff != d.MaxBackoff || got.AttemptTimeout != d.AttemptTimeout {
		t.Errorf("zero fields not defaulted: %+v", got)
	}
}
