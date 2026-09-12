// Package checkin runs the agent's periodic check-in loop.
package checkin

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"retune/internal/agent/client"
	"retune/internal/protocol"
)

const (
	DefaultInterval = 5 * time.Minute
	firstBackoff    = 30 * time.Second
	maxBackoff      = 30 * time.Minute
	revokedRetry    = 24 * time.Hour
)

// ErrUnenrolled means the server has unenrolled this device; the loop stops
// because the local identity is gone.
var ErrUnenrolled = errors.New("device was unenrolled")

// Checker is the part of the client the loop needs.
type Checker interface {
	Checkin(ctx context.Context, req protocol.CheckinRequest) (protocol.CheckinResponse, error)
}

// Loop checks in periodically. It never exits on errors.
type Loop struct {
	Client Checker
	Facts  func() protocol.CheckinRequest
	Log    *slog.Logger
	Rand   func() float64 // uniform in [0, 1)

	interval time.Duration
	failures int
}

// Run checks in until ctx is cancelled, or until the device is unenrolled.
func (l *Loop) Run(ctx context.Context) error {
	for {
		wait, err := l.RunOnce(ctx)
		if errors.Is(err, ErrUnenrolled) {
			return err
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil
		case <-t.C:
		}
	}
}

// RunOnce performs one check-in and returns how long to wait before the next.
// Errors are logged and returned for callers that want them (e.g. --once).
func (l *Loop) RunOnce(ctx context.Context) (wait time.Duration, err error) {
	if l.interval == 0 {
		l.interval = DefaultInterval
	}
	defer func() {
		if r := recover(); r != nil {
			l.failures++
			l.Log.Error("check-in panicked", "panic", r)
			wait, err = Backoff(l.failures), fmt.Errorf("check-in panicked: %v", r)
		}
	}()

	resp, err := l.Client.Checkin(ctx, l.Facts())
	var httpErr *client.HTTPError
	switch {
	case errors.Is(err, ErrUnenrolled):
		return 0, err
	case err == nil:
		l.failures = 0
		if resp.IntervalSeconds > 0 {
			l.interval = time.Duration(resp.IntervalSeconds) * time.Second
		}
		return Jitter(l.interval, l.Rand()), nil
	case errors.As(err, &httpErr) && httpErr.Status == http.StatusUnauthorized:
		l.Log.Error("server rejected this device's identity; it may be retired or replaced", "error", err)
		return revokedRetry, err
	default:
		l.failures++
		l.Log.Warn("check-in failed", "error", err, "consecutive_failures", l.failures)
		return Backoff(l.failures), err
	}
}

// Jitter spreads d by ±20%: r=0 → 0.8d, r=0.5 → d, r→1 → 1.2d.
func Jitter(d time.Duration, r float64) time.Duration {
	return time.Duration(float64(d) * (0.8 + 0.4*r))
}

// Backoff is 30s doubled per consecutive failure, capped at 30 minutes.
func Backoff(failures int) time.Duration {
	d := firstBackoff
	for i := 1; i < failures && d < maxBackoff; i++ {
		d *= 2
	}
	return min(d, maxBackoff)
}
