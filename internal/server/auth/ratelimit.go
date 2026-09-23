package auth

import (
	"sync"
	"time"
)

// maxLimiterKeys bounds how many keys a Limiter remembers. Keys are whatever
// a caller typed as an email, so without a bound anyone could fill memory
// with failures for addresses nobody has.
const maxLimiterKeys = 100_000

// Limiter counts recent failures per key, in memory. A restart forgets them,
// which is acceptable for slowing down password guessing.
type Limiter struct {
	max    int
	window time.Duration
	now    func() time.Time

	mu       sync.Mutex
	failures map[string][]time.Time
}

// NewLimiter allows max failures per key within window.
func NewLimiter(max int, window time.Duration, now func() time.Time) *Limiter {
	if now == nil {
		now = time.Now
	}
	return &Limiter{max: max, window: window, now: now, failures: map[string][]time.Time{}}
}

// Allowed reports whether the key may attempt again.
func (l *Limiter) Allowed(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.recent(key)) < l.max
}

// Fail records one failed attempt.
func (l *Limiter) Fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	recent := l.recent(key)
	if len(recent) == 0 && len(l.failures) >= maxLimiterKeys {
		l.evict()
	}
	l.failures[key] = append(recent, l.now())
}

// evict makes room for a new key: first by forgetting every key whose
// failures have all expired, and if that frees nothing, by forgetting one at
// random - which lets somebody filling the table make it forget a key, but
// never grow without bound. Callers hold the lock.
func (l *Limiter) evict() {
	for key := range l.failures {
		l.recent(key)
	}
	if len(l.failures) < maxLimiterKeys {
		return
	}
	for key := range l.failures {
		delete(l.failures, key)
		return
	}
}

// Reset clears a key's failures after a success.
func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.failures, key)
}

// recent drops expired entries, and the key itself once none are left, so
// merely asking about a key never makes the table remember it. Callers hold
// the lock.
func (l *Limiter) recent(key string) []time.Time {
	entries, ok := l.failures[key]
	if !ok {
		return nil
	}
	cutoff := l.now().Add(-l.window)
	kept := entries[:0]
	for _, at := range entries {
		if at.After(cutoff) {
			kept = append(kept, at)
		}
	}
	if len(kept) == 0 {
		delete(l.failures, key)
		return nil
	}
	l.failures[key] = kept
	return kept
}

// size is how many keys are remembered, for tests.
func (l *Limiter) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.failures)
}
