package auth

import (
	"context"
	"time"

	"retune/internal/server/store"
)

// Throttle counts failed sign-ins per account and says when there have been
// too many.
type Throttle interface {
	Allowed(ctx context.Context, key string) (bool, error)
	Fail(ctx context.Context, key string) error
	Reset(ctx context.Context, key string) error
}

// StoreThrottle keeps the count in the database, so the limit holds across
// every server sharing it: an attacker spread across replicas by a load
// balancer gets one allowance, not one per replica.
type StoreThrottle struct {
	Store  *store.Store
	Max    int
	Window time.Duration
	Now    func() time.Time
}

func (t *StoreThrottle) now() time.Time {
	if t.Now != nil {
		return t.Now()
	}
	return time.Now()
}

func (t *StoreThrottle) Allowed(ctx context.Context, key string) (bool, error) {
	n, err := t.Store.Q().CountLoginFailures(ctx, key, t.now().Add(-t.Window))
	return n < t.Max, err
}

func (t *StoreThrottle) Fail(ctx context.Context, key string) error {
	now := t.now()
	return t.Store.Q().RecordLoginFailure(ctx, key, now, now.Add(-t.Window))
}

func (t *StoreThrottle) Reset(ctx context.Context, key string) error {
	return t.Store.Q().ClearLoginFailures(ctx, key)
}

// memoryThrottle adapts the in-memory Limiter.
type memoryThrottle struct{ l *Limiter }

func (m memoryThrottle) Allowed(_ context.Context, key string) (bool, error) {
	return m.l.Allowed(key), nil
}
func (m memoryThrottle) Fail(_ context.Context, key string) error {
	m.l.Fail(key)
	return nil
}
func (m memoryThrottle) Reset(_ context.Context, key string) error {
	m.l.Reset(key)
	return nil
}
