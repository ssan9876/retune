package winupdate

import (
	"context"
	"io"
	"testing"
	"time"

	"retune/internal/protocol"
)

type memStore struct {
	st    protocol.UpdateStatus
	found bool
}

func (m *memStore) UpdateScan() (protocol.UpdateStatus, bool, error) { return m.st, m.found, nil }
func (m *memStore) SetUpdateScan(st protocol.UpdateStatus) error {
	m.st, m.found = st, true
	return nil
}
func (m *memStore) ClearUpdateScan() error {
	m.found = false
	return nil
}

// runnerFunc counts the searches a Runner is asked to make.
func runnerFunc(count func(), r Runner) Runner { return counting{count, r} }

type counting struct {
	count func()
	r     Runner
}

func (c counting) RunPowerShell(ctx context.Context, script string, stdout, stderr io.Writer) (int, error) {
	c.count()
	return c.r.RunPowerShell(ctx, script, stdout, stderr)
}

func TestCache(t *testing.T) {
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	r := &fakeRunner{out: withSecurity}
	runs := 0
	counted := runnerFunc(func() { runs++ }, r)
	c := &Cache{Store: &memStore{}, Runner: counted, Now: func() time.Time { return now }, MaxAge: 24 * time.Hour}

	if st := c.Status(context.Background()); len(st.Pending) != 2 || runs != 1 {
		t.Fatalf("first: %+v, %d runs", st, runs)
	}
	now = now.Add(23 * time.Hour)
	if c.Status(context.Background()); runs != 1 {
		t.Fatalf("a fresh search is reused, got %d runs", runs)
	}
	now = now.Add(2 * time.Hour)
	if c.Status(context.Background()); runs != 2 {
		t.Fatalf("a day-old search is repeated, got %d runs", runs)
	}
	// A failed search is retried after an hour, not a day.
	r.code, r.errOut = 1, "offline"
	now = now.Add(25 * time.Hour)
	if st := c.Status(context.Background()); st.Error == "" || runs != 3 {
		t.Fatalf("failing: %+v, %d runs", st, runs)
	}
	now = now.Add(30 * time.Minute)
	if c.Status(context.Background()); runs != 3 {
		t.Fatalf("a failure is remembered for a while, got %d runs", runs)
	}
	now = now.Add(time.Hour)
	if c.Status(context.Background()); runs != 4 {
		t.Fatalf("and retried after an hour, got %d runs", runs)
	}
	// After installing, the next inventory searches afresh, even within the
	// hour a failure is remembered for.
	r.code, r.errOut = 0, ""
	if c.Status(context.Background()); runs != 4 {
		t.Fatalf("still within the hour, got %d runs", runs)
	}
	_ = c.Invalidate()
	if st := c.Status(context.Background()); runs != 5 || st.Error != "" {
		t.Fatalf("after Invalidate, got %d runs", runs)
	}
}
