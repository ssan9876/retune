package sweeper_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"retune/internal/server/store"
	"retune/internal/server/store/storetest"
	"retune/internal/server/sweeper"
)

type fakeSink struct {
	name string
	mu   sync.Mutex
	got  []store.AuditEntry
	fail error
}

func (f *fakeSink) Name() string { return f.name }

func (f *fakeSink) Send(_ context.Context, es []store.AuditEntry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return f.fail
	}
	f.got = append(f.got, es...)
	return nil
}

func (f *fakeSink) actions() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, e := range f.got {
		out = append(out, e.Action)
	}
	return out
}

func TestAuditStreamJob(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	base := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	audit := func(action string, at time.Time) {
		t.Helper()
		if err := st.Q().InsertAudit(ctx, store.AuditEntry{Actor: "alice", Action: action, TargetKind: "x", TargetID: "1", At: at}); err != nil {
			t.Fatal(err)
		}
	}
	good := &fakeSink{name: "good"}
	bad := &fakeSink{name: "bad", fail: errors.New("siem down")}
	job := sweeper.AuditStreamJob(good, bad)
	clock := base
	r := &sweeper.Runner{Store: st, Log: discard(), Now: func() time.Time { return clock }}

	// History from before a destination is first seen isn't sent to it.
	audit("before", base.Add(-5*time.Minute))
	if _, _, err := r.RunOnce(ctx, job); err != nil {
		t.Fatalf("first run: %v", err)
	}
	audit("one", base.Add(time.Minute))
	audit("two", base.Add(2*time.Minute))

	// Entries younger than the lag wait: one committing late could still
	// land behind them.
	clock = base.Add(150 * time.Second)
	if _, _, err := r.RunOnce(ctx, job); err != nil {
		t.Fatalf("nothing was due, so nothing could fail: %v", err)
	}
	if got := good.actions(); len(got) != 0 {
		t.Fatalf("sent %v before the lag had passed", got)
	}

	// Once old enough, they go, in order and once. The failing sink doesn't
	// hold up the other.
	clock = base.Add(10 * time.Minute)
	n, _, err := r.RunOnce(ctx, job)
	if err == nil {
		t.Fatal("a failing sink must fail the run")
	}
	if n != 2 {
		t.Fatalf("sent %d, want 2", n)
	}
	if got := good.actions(); len(got) != 2 || got[0] != "one" || got[1] != "two" {
		t.Fatalf("good got %v", got)
	}
	if _, _, err := r.RunOnce(ctx, job); err == nil {
		t.Fatal("a failing sink must fail the run")
	}
	if got := good.actions(); len(got) != 2 {
		t.Fatalf("resent: %v", got)
	}

	// The failed sink recovers and catches up from where it was.
	bad.mu.Lock()
	bad.fail = nil
	bad.mu.Unlock()
	if _, _, err := r.RunOnce(ctx, job); err != nil {
		t.Fatalf("recovered run: %v", err)
	}
	if got := bad.actions(); len(got) != 2 || got[0] != "one" || got[1] != "two" {
		t.Fatalf("bad got %v after recovering", got)
	}
}

func TestAuditStreamJobPagesThroughABacklog(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	sink := &fakeSink{name: "s"}
	job := sweeper.AuditStreamJob(sink)
	base := time.Now().Add(-time.Hour)
	clock := base
	r := &sweeper.Runner{Store: st, Log: discard(), Now: func() time.Time { return clock }}
	if _, _, err := r.RunOnce(ctx, job); err != nil {
		t.Fatal(err)
	}
	// More than two batches of 500, several sharing a time so the cursor's
	// id breaks the tie.
	for i := 0; i < 1203; i++ {
		at := base.Add(time.Duration(i/3) * time.Millisecond)
		if err := st.Q().InsertAudit(ctx, store.AuditEntry{Actor: "a", Action: "bulk", TargetKind: "x", TargetID: "1", At: at}); err != nil {
			t.Fatal(err)
		}
	}
	clock = base.Add(10 * time.Minute)
	n, _, err := r.RunOnce(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1203 || len(sink.actions()) != 1203 {
		t.Fatalf("sent %d (%d received), want 1203", n, len(sink.actions()))
	}
	seen := map[string]bool{}
	for _, e := range sink.got {
		if seen[e.ID.String()] {
			t.Fatalf("entry %s sent twice", e.ID)
		}
		seen[e.ID.String()] = true
	}
}
