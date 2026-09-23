package sweeper

import (
	"context"
	"time"

	"retune/internal/server/store"
)

// Retention is how long each kind of history is kept; zero keeps it forever.
// BatchSize and MaxBatches are for tests: zero takes the defaults.
type Retention struct {
	Audit       time.Duration
	Commands    time.Duration
	ScriptRuns  time.Duration
	AppInstalls time.Duration

	BatchSize  int
	MaxBatches int
}

const (
	defaultRetentionBatch = 5000
	// defaultRetentionMaxBatches caps one run at a million rows per table. A
	// first run over years of history would otherwise hold the advisory lock
	// for as long as it takes; stopping short and picking up on the next tick
	// costs nothing, since the rows are only getting older.
	defaultRetentionMaxBatches = 200
)

// RetentionJob deletes history past its horizon. It runs hourly rather than
// daily because a job's ticker starts with the process: a daily job on a
// server restarted more often than that would never run at all. When nothing
// has aged out, a run is four index lookups that find nothing.
func RetentionJob(r Retention) Job {
	batch := r.BatchSize
	if batch <= 0 {
		batch = defaultRetentionBatch
	}
	maxBatches := r.MaxBatches
	if maxBatches <= 0 {
		maxBatches = defaultRetentionMaxBatches
	}
	return Job{
		Name: "retention.prune", LockID: lockRetention, Interval: time.Hour,
		Run: func(ctx context.Context, q *store.Queries, now time.Time) (int64, error) {
			tables := []struct {
				key     string
				horizon time.Duration
				del     func(context.Context, time.Time, int) (int64, error)
			}{
				{"audit_log", r.Audit, q.DeleteAuditBefore},
				{"commands", r.Commands, q.DeleteFinishedCommandsBefore},
				{"script_runs", r.ScriptRuns, q.DeleteScriptRunsBefore},
				{"app_installs", r.AppInstalls, q.DeleteAppInstallsBefore},
			}
			counts := map[string]any{}
			var total int64
			for _, t := range tables {
				if t.horizon <= 0 {
					continue
				}
				cutoff := now.Add(-t.horizon)
				var removed int64
				for i := 0; i < maxBatches; i++ {
					n, err := t.del(ctx, cutoff, batch)
					if err != nil {
						return total, err
					}
					removed += n
					if n < int64(batch) {
						break
					}
				}
				counts[t.key] = removed
				total += removed
			}
			if total == 0 {
				return 0, nil
			}
			// History disappearing should leave a trace of its own. One entry
			// per run that removed anything, at most one an hour, is a trace
			// that cannot itself grow without bound.
			err := q.InsertAudit(ctx, store.AuditEntry{
				Actor: "system", Action: "retention.pruned", TargetKind: "retention", Details: counts,
			})
			return total, err
		},
	}
}
