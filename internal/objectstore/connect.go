package objectstore

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/minio/minio-go/v7"
)

// ErrBucketNotFound is returned by Ping (and by Connect once its retries
// are spent) when the endpoint is reachable but the configured bucket
// doesn't exist.
var ErrBucketNotFound = errors.New("objectstore: bucket does not exist")

// RetryPolicy controls Connect's exponential backoff. Zero fields take the
// DefaultRetryPolicy value.
//
// minio-go already retries each individual request (up to 10 times, with
// waits capped at 1s), which absorbs a blip on a live connection. That
// isn't enough for "the object store isn't up yet", e.g. MinIO still
// starting alongside farmer, which is what this policy is for.
type RetryPolicy struct {
	// MaxAttempts is the total number of connection attempts, including
	// the first.
	MaxAttempts int
	// InitialBackoff is the wait before the second attempt; each later
	// wait doubles, up to MaxBackoff.
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
	// AttemptTimeout bounds each attempt, so minio-go's own per-request
	// retries against an unreachable host can't stretch one attempt out.
	AttemptTimeout time.Duration
	// OnRetry, if set, is called after each failed attempt that will be
	// retried, with the wait before the next one — for logging.
	OnRetry func(attempt int, wait time.Duration, err error)
}

// DefaultRetryPolicy returns the policy Connect uses for zero fields:
// 8 attempts, waiting 1s, 2s, 4s, … capped at 30s (about 90s in total
// before jitter), with 10s per attempt.
func DefaultRetryPolicy() RetryPolicy {
	return RetryPolicy{
		MaxAttempts:    8,
		InitialBackoff: time.Second,
		MaxBackoff:     30 * time.Second,
		AttemptTimeout: 10 * time.Second,
	}
}

func (p RetryPolicy) withDefaults() RetryPolicy {
	d := DefaultRetryPolicy()
	if p.MaxAttempts <= 0 {
		p.MaxAttempts = d.MaxAttempts
	}
	if p.InitialBackoff <= 0 {
		p.InitialBackoff = d.InitialBackoff
	}
	if p.MaxBackoff <= 0 {
		p.MaxBackoff = d.MaxBackoff
	}
	if p.AttemptTimeout <= 0 {
		p.AttemptTimeout = d.AttemptTimeout
	}
	return p
}

// backoff returns the un-jittered wait after the given failed attempt
// (1-based): InitialBackoff doubled attempt-1 times, capped at MaxBackoff.
func (p RetryPolicy) backoff(attempt int) time.Duration {
	b := p.InitialBackoff
	for i := 1; i < attempt; i++ {
		if b >= p.MaxBackoff/2 {
			return p.MaxBackoff
		}
		b *= 2
	}
	return min(b, p.MaxBackoff)
}

// jitter spreads a wait over [b/2, b], so replicas that start together
// don't retry against the object store in lockstep.
func jitter(b time.Duration) time.Duration {
	half := b / 2
	if half <= 0 {
		return b
	}
	return half + rand.N(half+1)
}

// Ping checks that the endpoint is reachable, the credentials are
// accepted, and the bucket exists.
func (s *Store) Ping(ctx context.Context) error {
	ok, err := s.client.BucketExists(ctx, s.bucket)
	if err != nil {
		return fmt.Errorf("objectstore: checking bucket %s: %w", s.bucket, err)
	}
	if !ok {
		return fmt.Errorf("%w: %s", ErrBucketNotFound, s.bucket)
	}
	return nil
}

// Connect opens cfg (see Open) and waits until the store answers Ping,
// retrying with exponential backoff and jitter per p. Configuration
// errors and rejected credentials fail immediately: retrying can't fix
// them. It gives up once p.MaxAttempts are spent or ctx is done,
// returning the last error.
func Connect(ctx context.Context, cfg Config, p RetryPolicy) (*Store, error) {
	store, err := Open(cfg)
	if err != nil {
		return nil, err
	}
	p = p.withDefaults()
	for attempt := 1; ; attempt++ {
		attemptCtx, cancel := context.WithTimeout(ctx, p.AttemptTimeout)
		err = store.Ping(attemptCtx)
		cancel()
		if err == nil {
			return store, nil
		}
		if isPermanent(err) {
			return nil, err
		}
		if ctx.Err() != nil {
			return nil, fmt.Errorf("objectstore: giving up connecting to %s: %w", cfg.Endpoint, errors.Join(ctx.Err(), err))
		}
		if attempt >= p.MaxAttempts {
			return nil, fmt.Errorf("objectstore: giving up connecting to %s after %d attempts: %w", cfg.Endpoint, attempt, err)
		}
		wait := jitter(p.backoff(attempt))
		if p.OnRetry != nil {
			p.OnRetry(attempt, wait, err)
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil, fmt.Errorf("objectstore: giving up connecting to %s: %w", cfg.Endpoint, errors.Join(ctx.Err(), err))
		case <-t.C:
		}
	}
}

// isPermanent reports whether a Ping error can't be fixed by waiting:
// the server rejected the credentials. Ping wraps the minio error, and
// minio.ToErrorResponse doesn't unwrap, hence errors.As.
func isPermanent(err error) bool {
	var resp minio.ErrorResponse
	if !errors.As(err, &resp) {
		return false
	}
	switch resp.Code {
	case "AccessDenied", "InvalidAccessKeyId", "SignatureDoesNotMatch":
		return true
	}
	return false
}
