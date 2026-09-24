package checkin

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"retune/internal/agent/client"
)

type fakeWaiter struct {
	answers []waitAnswer
	calls   int
}

type waitAnswer struct {
	woke bool
	err  error
}

func (f *fakeWaiter) WaitForWork(ctx context.Context, limit time.Duration) (bool, error) {
	f.calls++
	if len(f.answers) == 0 {
		<-ctx.Done()
		return false, ctx.Err()
	}
	a := f.answers[0]
	f.answers = f.answers[1:]
	return a.woke, a.err
}

func TestPauseChecksInWhenWoken(t *testing.T) {
	w := &fakeWaiter{answers: []waitAnswer{{woke: false}, {woke: true}}}
	l := &Loop{Log: slog.New(slog.DiscardHandler), Waiter: w}
	start := time.Now()
	if !l.pause(context.Background(), time.Hour) {
		t.Fatal("pause ended as if cancelled")
	}
	// Woken on the second wait: back after the minimum gap, not an hour.
	if took := time.Since(start); took > 10*time.Second || took < minWakeGap || w.calls != 2 {
		t.Fatalf("took %s over %d waits", took, w.calls)
	}
}

func TestPauseFallsBackToSleeping(t *testing.T) {
	// An old server: 404, then waiting is off for an hour.
	w := &fakeWaiter{answers: []waitAnswer{{err: &client.HTTPError{Status: http.StatusNotFound}}}}
	l := &Loop{Log: slog.New(slog.DiscardHandler), Waiter: w}
	start := time.Now()
	if !l.pause(context.Background(), 200*time.Millisecond) || time.Since(start) < 200*time.Millisecond {
		t.Fatal("a 404 must fall back to sleeping out the interval")
	}
	if !l.pause(context.Background(), 50*time.Millisecond) || w.calls != 1 {
		t.Fatalf("waiting should stay off after a 404, got %d calls", w.calls)
	}
	// Any other failure sleeps out this interval, and tries again next time.
	w2 := &fakeWaiter{answers: []waitAnswer{{err: errors.New("connection reset")}}}
	l2 := &Loop{Log: slog.New(slog.DiscardHandler), Waiter: w2}
	start = time.Now()
	if !l2.pause(context.Background(), 150*time.Millisecond) || time.Since(start) < 150*time.Millisecond {
		t.Fatal("an error must sleep out the interval")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if l2.pause(ctx, time.Hour) {
		t.Fatal("a cancelled context must end the pause")
	}
}
