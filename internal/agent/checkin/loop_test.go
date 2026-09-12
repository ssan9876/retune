package checkin

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"retune/internal/agent/client"
	"retune/internal/protocol"
)

type step struct {
	resp  protocol.CheckinResponse
	err   error
	panic bool
}

type fakeChecker struct {
	steps []step
	calls int
}

func (f *fakeChecker) Checkin(context.Context, protocol.CheckinRequest) (protocol.CheckinResponse, error) {
	s := f.steps[f.calls]
	f.calls++
	if s.panic {
		panic("boom")
	}
	return s.resp, s.err
}

func newLoop(c Checker) *Loop {
	return &Loop{
		Client: c,
		Facts:  func() protocol.CheckinRequest { return protocol.CheckinRequest{} },
		Log:    slog.New(slog.DiscardHandler),
		Rand:   func() float64 { return 0.5 }, // Jitter(d, 0.5) == d
	}
}

func TestJitter(t *testing.T) {
	if got := Jitter(100*time.Second, 0); got != 80*time.Second {
		t.Errorf("Jitter(100s, 0) = %s", got)
	}
	if got := Jitter(100*time.Second, 0.5); got != 100*time.Second {
		t.Errorf("Jitter(100s, 0.5) = %s", got)
	}
	if got := Jitter(100*time.Second, 0.9999); got >= 120*time.Second {
		t.Errorf("Jitter(100s, ~1) = %s, want < 120s", got)
	}
}

func TestBackoff(t *testing.T) {
	want := []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 16 * time.Minute, 30 * time.Minute, 30 * time.Minute}
	for i, w := range want {
		if got := Backoff(i + 1); got != w {
			t.Errorf("Backoff(%d) = %s, want %s", i+1, got, w)
		}
	}
}

func TestRunOnce(t *testing.T) {
	ctx := context.Background()
	netErr := errors.New("connection refused")
	f := &fakeChecker{steps: []step{
		{resp: protocol.CheckinResponse{IntervalSeconds: 120}},
		{err: netErr},
		{err: &client.HTTPError{Status: 503}},
		{resp: protocol.CheckinResponse{}},
		{err: &client.HTTPError{Status: 401, Code: "device_not_active"}},
		{panic: true},
	}}
	l := newLoop(f)
	expect := []struct {
		wait    time.Duration
		wantErr bool
	}{
		{120 * time.Second, false}, // server interval
		{30 * time.Second, true},   // first failure
		{time.Minute, true},        // second failure
		{120 * time.Second, false}, // success resets failures, keeps last interval
		{24 * time.Hour, true},     // revoked
		{30 * time.Second, true},   // panic recovered, counted as failure
	}
	for i, e := range expect {
		wait, err := l.RunOnce(ctx)
		if wait != e.wait || (err != nil) != e.wantErr {
			t.Fatalf("call %d: wait=%s err=%v, want wait=%s wantErr=%v", i, wait, err, e.wait, e.wantErr)
		}
	}
}

func TestRunOnceDefaultInterval(t *testing.T) {
	l := newLoop(&fakeChecker{steps: []step{{resp: protocol.CheckinResponse{}}}})
	if wait, err := l.RunOnce(context.Background()); err != nil || wait != DefaultInterval {
		t.Fatalf("wait=%s err=%v", wait, err)
	}
}

func TestUnenrolledStopsRun(t *testing.T) {
	f := &fakeChecker{steps: []step{{err: fmt.Errorf("checking in: %w", ErrUnenrolled)}}}
	err := newLoop(f).Run(context.Background())
	if !errors.Is(err, ErrUnenrolled) {
		t.Fatalf("Run = %v, want ErrUnenrolled", err)
	}
	if f.calls != 1 {
		t.Fatalf("calls = %d, want 1", f.calls)
	}
}

func TestRunOnceUnenrolled(t *testing.T) {
	f := &fakeChecker{steps: []step{{err: ErrUnenrolled}}}
	wait, err := newLoop(f).RunOnce(context.Background())
	if !errors.Is(err, ErrUnenrolled) || wait != 0 {
		t.Fatalf("RunOnce = %s, %v", wait, err)
	}
}

func TestRunStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	f := &fakeChecker{steps: []step{{resp: protocol.CheckinResponse{IntervalSeconds: 3600}}}}
	done := make(chan struct{})
	go func() { _ = newLoop(f).Run(ctx); close(done) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}
