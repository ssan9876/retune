package sweeper

import (
	"context"
	"time"

	"retune/internal/server/store"
)

// Lock IDs are fixed so they stay stable across restarts and replicas.
const (
	lockExpireCommands  = 5274001
	lockCleanupSessions = 5274002
)

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
