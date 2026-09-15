package sweeper

import (
	"context"
	"time"

	"retune/internal/server/store"
)

// Lock IDs are fixed so they stay stable across restarts and replicas.
const (
	lockExpireCommands     = 5274001
	lockCleanupSessions    = 5274002
	lockEvaluateGroups     = 5274003
	lockEvaluateCompliance = 5274004
)

// GroupEvaluator recomputes dynamic group membership.
type GroupEvaluator interface {
	EvaluateAll(ctx context.Context) (int, error)
}

// GroupJob re-evaluates every dynamic group. Its interval is fixed at the 15
// minutes the design calls for, independent of the configured sweep interval,
// because it is a good deal more expensive than expiring a few rows.
func GroupJob(g GroupEvaluator) Job {
	return Job{
		Name: "groups.evaluate", LockID: lockEvaluateGroups, Interval: 15 * time.Minute,
		Run: func(ctx context.Context, _ *store.Queries, _ time.Time) (int64, error) {
			n, err := g.EvaluateAll(ctx)
			return int64(n), err
		},
	}
}

// ComplianceEvaluator re-scores every active device's compliance policies.
type ComplianceEvaluator interface {
	EvaluateActive(ctx context.Context, q *store.Queries, now time.Time) (int64, error)
}

// ComplianceJob re-evaluates compliance for every active device. Its interval
// is fixed at 15 minutes, the same as GroupJob and for the same reason: it is
// too expensive to ride along with the configurable sweep interval, and
// ingest-time evaluation (inventory.Service.Compliance) is already the fast
// path for devices that check in.
func ComplianceJob(c ComplianceEvaluator) Job {
	return Job{
		Name: "compliance.evaluate", LockID: lockEvaluateCompliance, Interval: 15 * time.Minute,
		Run: c.EvaluateActive,
	}
}

// DefaultJobs are the maintenance jobs every server runs.
func DefaultJobs(interval time.Duration) []Job {
	return []Job{
		{
			// Commands used to be expired only when a device checked in, so a
			// command queued for a machine that never came back stayed queued
			// forever.
			Name: "commands.expire", LockID: lockExpireCommands, Interval: interval,
			Run: func(ctx context.Context, q *store.Queries, now time.Time) (int64, error) {
				return q.ExpireCommands(ctx, now)
			},
		},
		{
			Name: "sessions.cleanup", LockID: lockCleanupSessions, Interval: interval,
			Run: func(ctx context.Context, q *store.Queries, now time.Time) (int64, error) {
				return q.DeleteExpiredSessions(ctx, now)
			},
		},
	}
}
