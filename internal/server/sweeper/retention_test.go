package sweeper_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"retune/internal/server/store"
	"retune/internal/server/store/storetest"
	"retune/internal/server/sweeper"
)

func seedOldRuns(t *testing.T, st *store.Store, n int, age time.Duration) {
	t.Helper()
	ctx := context.Background()
	now := time.Now()
	dev := store.Device{
		ID: uuid.New(), Hostname: "retention-" + uuid.NewString()[:8], Status: store.DeviceActive,
		CertSerial: uuid.NewString(), CertExpiresAt: now.Add(24 * time.Hour), EnrolledAt: now,
	}
	if err := st.Q().CreateDevice(ctx, dev); err != nil {
		t.Fatal(err)
	}
	at := now.Add(-age)
	for i := 0; i < n; i++ {
		if err := st.Q().InsertScriptRun(ctx, store.ScriptRun{
			ID: uuid.New(), ScriptID: uuid.New(), Version: 1, DeviceID: dev.ID,
			Status: "succeeded", Phase: "script", StartedAt: at, FinishedAt: at,
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func retentionAudits(t *testing.T, st *store.Store) []store.AuditEntry {
	t.Helper()
	all, err := st.Q().ListAudit(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	var out []store.AuditEntry
	for _, e := range all {
		if e.Action == "retention.pruned" {
			out = append(out, e)
		}
	}
	return out
}

func TestRetentionJobPrunesAndLeavesATrace(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	seedOldRuns(t, st, 3, 100*24*time.Hour)
	seedOldRuns(t, st, 2, time.Hour)
	r := &sweeper.Runner{Store: st, Log: discard(), Now: time.Now}
	job := sweeper.RetentionJob(sweeper.Retention{ScriptRuns: 90 * 24 * time.Hour})

	n, ran, err := r.RunOnce(ctx, job)
	if err != nil || !ran || n != 3 {
		t.Fatalf("RunOnce = %d %v %v; want 3 rows", n, ran, err)
	}
	audits := retentionAudits(t, st)
	if len(audits) != 1 {
		t.Fatalf("want one retention.pruned entry, got %d", len(audits))
	}
	if got := audits[0].Details["script_runs"]; got != float64(3) {
		t.Errorf("details = %v, want script_runs: 3", audits[0].Details)
	}
	if _, ok := audits[0].Details["audit_log"]; ok {
		t.Error("a table whose retention is off should not be reported")
	}

	// A second run finds nothing and says nothing.
	if n, _, err := r.RunOnce(ctx, job); err != nil || n != 0 {
		t.Fatalf("second run = %d %v", n, err)
	}
	if got := len(retentionAudits(t, st)); got != 1 {
		t.Errorf("a run that removes nothing must not write an audit entry, have %d", got)
	}
}

// A horizon of zero keeps that history forever.
func TestRetentionZeroKeepsForever(t *testing.T) {
	st := storetest.New(t)
	seedOldRuns(t, st, 2, 10*365*24*time.Hour)
	r := &sweeper.Runner{Store: st, Log: discard(), Now: time.Now}
	n, _, err := r.RunOnce(context.Background(), sweeper.RetentionJob(sweeper.Retention{}))
	if err != nil || n != 0 {
		t.Fatalf("RunOnce = %d %v; nothing should go", n, err)
	}
}

// One run stops after MaxBatches, and the next run carries on.
func TestRetentionStopsAtTheBatchCap(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	seedOldRuns(t, st, 7, 100*24*time.Hour)
	r := &sweeper.Runner{Store: st, Log: discard(), Now: time.Now}
	job := sweeper.RetentionJob(sweeper.Retention{ScriptRuns: 90 * 24 * time.Hour, BatchSize: 2, MaxBatches: 2})
	for i, want := range []int64{4, 3, 0} {
		if n, _, err := r.RunOnce(ctx, job); err != nil || n != want {
			t.Fatalf("run %d = %d %v; want %d", i+1, n, err, want)
		}
	}
}

func TestStatsRecordEachOutcome(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	stats := sweeper.NewStats()
	r := &sweeper.Runner{Store: st, Log: discard(), Now: time.Now, Stats: stats}

	ok := sweeper.Job{Name: "t.ok", LockID: 991001, Interval: time.Hour,
		Run: func(context.Context, *store.Queries, time.Time) (int64, error) { return 5, nil }}
	bad := sweeper.Job{Name: "t.bad", LockID: 991002, Interval: time.Hour,
		Run: func(context.Context, *store.Queries, time.Time) (int64, error) { return 0, errors.New("boom") }}
	_, _, _ = r.RunOnce(ctx, ok)
	_, _, _ = r.RunOnce(ctx, ok)
	_, _, _ = r.RunOnce(ctx, bad)

	snap := stats.Snapshot()
	if len(snap) != 2 || snap[0].Name != "t.bad" || snap[1].Name != "t.ok" {
		t.Fatalf("snapshot = %+v", snap)
	}
	if snap[0].Runs[sweeper.ResultError] != 1 || !snap[0].LastSuccess.IsZero() {
		t.Errorf("t.bad = %+v", snap[0].JobStats)
	}
	if snap[1].Runs[sweeper.ResultOK] != 2 || snap[1].Rows != 10 || snap[1].LastSuccess.IsZero() {
		t.Errorf("t.ok = %+v", snap[1].JobStats)
	}
}
