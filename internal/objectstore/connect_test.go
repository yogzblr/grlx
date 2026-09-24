package objectstore_test

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gogrlx/grlx/v2/internal/objectstore"
	"github.com/gogrlx/grlx/v2/internal/objectstore/objectstoretest"
)

type retryCall struct {
	attempt int
	wait    time.Duration
	err     error
}

// fastPolicy keeps real waits in the millisecond range and records every
// retry.
func fastPolicy(calls *[]retryCall) objectstore.RetryPolicy {
	return objectstore.RetryPolicy{
		MaxAttempts:    4,
		InitialBackoff: 4 * time.Millisecond,
		MaxBackoff:     10 * time.Millisecond,
		AttemptTimeout: 2 * time.Second,
		OnRetry: func(attempt int, wait time.Duration, err error) {
			*calls = append(*calls, retryCall{attempt, wait, err})
		},
	}
}

func TestConnectSucceedsFirstTry(t *testing.T) {
	srv := objectstoretest.NewServer(t)
	var calls []retryCall

	store, err := objectstore.Connect(context.Background(), srv.Config(), fastPolicy(&calls))
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if len(calls) != 0 {
		t.Errorf("expected no retries, got %+v", calls)
	}
	if err := store.Put(context.Background(), "k", []byte("v")); err != nil {
		t.Errorf("connected store not usable: %v", err)
	}
}

func TestConnectRetriesWithExponentialBackoff(t *testing.T) {
	srv := objectstoretest.NewServer(t)
	// The bucket "appears" on the third attempt, as when a bucket-creation
	// job races farmer's startup.
	srv.FailNext(2, 404, "NoSuchBucket")
	var calls []retryCall

	if _, err := objectstore.Connect(context.Background(), srv.Config(), fastPolicy(&calls)); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if len(calls) != 2 {
		t.Fatalf("expected 2 retries, got %d: %+v", len(calls), calls)
	}
	for i, base := range []time.Duration{4 * time.Millisecond, 8 * time.Millisecond} {
		c := calls[i]
		if c.attempt != i+1 {
			t.Errorf("retry %d: attempt = %d", i, c.attempt)
		}
		if c.wait < base/2 || c.wait > base {
			t.Errorf("retry %d: wait %s outside jittered range [%s, %s]", i, c.wait, base/2, base)
		}
		if !errors.Is(c.err, objectstore.ErrBucketNotFound) {
			t.Errorf("retry %d: err = %v, want ErrBucketNotFound", i, c.err)
		}
	}
}

func TestConnectGivesUpAfterMaxAttempts(t *testing.T) {
	srv := objectstoretest.NewServer(t)
	cfg := srv.Config()
	cfg.Bucket = "missing-bucket"
	var calls []retryCall

	_, err := objectstore.Connect(context.Background(), cfg, fastPolicy(&calls))
	if !errors.Is(err, objectstore.ErrBucketNotFound) {
		t.Fatalf("expected ErrBucketNotFound, got %v", err)
	}
	if !strings.Contains(err.Error(), "after 4 attempts") {
		t.Errorf("error should say how many attempts were made: %v", err)
	}
	if len(calls) != 3 {
		t.Errorf("expected 3 retries for 4 attempts, got %d", len(calls))
	}
}

func TestConnectFailsFastOnRejectedCredentials(t *testing.T) {
	for _, code := range []string{"AccessDenied", "InvalidAccessKeyId", "SignatureDoesNotMatch"} {
		t.Run(code, func(t *testing.T) {
			srv := objectstoretest.NewServer(t)
			// A server rejecting credentials rejects every request (minio-go
			// itself may resend one), so keep failing rather than once.
			srv.FailNext(100, 403, code)
			var calls []retryCall

			if _, err := objectstore.Connect(context.Background(), srv.Config(), fastPolicy(&calls)); err == nil {
				t.Fatal("expected an error")
			}
			if len(calls) != 0 {
				t.Errorf("rejected credentials must not be retried, got %d retries", len(calls))
			}
		})
	}
}

func TestConnectFailsFastOnBadConfig(t *testing.T) {
	var calls []retryCall
	if _, err := objectstore.Connect(context.Background(), objectstore.Config{Bucket: "recipes"}, fastPolicy(&calls)); err == nil {
		t.Fatal("expected an error for an empty endpoint")
	}
	if len(calls) != 0 {
		t.Errorf("config errors must not be retried, got %d retries", len(calls))
	}
}

func TestConnectUnreachableEndpoint(t *testing.T) {
	// A port that was just listening and is now closed: connection refused.
	dead := httptest.NewServer(nil)
	endpoint := strings.TrimPrefix(dead.URL, "http://")
	dead.Close()

	var calls []retryCall
	p := fastPolicy(&calls)
	p.MaxAttempts = 3
	p.AttemptTimeout = 100 * time.Millisecond
	cfg := objectstore.Config{Endpoint: endpoint, AccessKeyID: "x", SecretAccessKey: "x", Bucket: "recipes"}

	start := time.Now()
	if _, err := objectstore.Connect(context.Background(), cfg, p); err == nil {
		t.Fatal("expected an error for an unreachable endpoint")
	}
	if len(calls) != 2 {
		t.Errorf("expected 2 retries, got %d", len(calls))
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("AttemptTimeout not bounding attempts: took %s", elapsed)
	}
}

func TestConnectStopsWhenContextCancelled(t *testing.T) {
	srv := objectstoretest.NewServer(t)
	cfg := srv.Config()
	cfg.Bucket = "missing-bucket"

	ctx, cancel := context.WithCancel(context.Background())
	p := objectstore.RetryPolicy{
		MaxAttempts:    10,
		InitialBackoff: time.Hour, // only a cancelled ctx can end this wait
		OnRetry:        func(int, time.Duration, error) { cancel() },
	}

	done := make(chan error, 1)
	go func() {
		_, err := objectstore.Connect(ctx, cfg, p)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Connect did not return after its context was cancelled")
	}
}
