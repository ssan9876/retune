// Package sweeper runs periodic maintenance jobs. Each job is guarded by a
// Postgres advisory lock so that only one server replica runs it per tick.
package sweeper

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"retune/internal/server/store"
)

// Job is one periodic maintenance task.
type Job struct {
	Name     string
	LockID   int64
	Interval time.Duration
	// Run does the work and reports how many rows it affected.
	Run func(ctx context.Context, q *store.Queries, now time.Time) (int64, error)
}

// Runner runs jobs on their own tickers until its context is cancelled.
type Runner struct {
	Store *store.Store
	Jobs  []Job
	Log   *slog.Logger
	Now   func() time.Time
	// Stats, when set, records every run for the metrics endpoint.
	Stats *Stats
}

// Start launches one goroutine per job and returns immediately.
func (r *Runner) Start(ctx context.Context) {
	for _, job := range r.Jobs {
		go r.loop(ctx, job)
	}
}

func (r *Runner) loop(ctx context.Context, job Job) {
	t := time.NewTicker(job.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			n, ran, err := r.runRecovered(ctx, job)
			switch {
			case err != nil:
				// A failing job is retried on the next tick; it never stops
				// the runner.
				r.Log.Warn("sweeper job failed", "job", job.Name, "error", err)
			case ran && n > 0:
				r.Log.Info("sweeper job ran", "job", job.Name, "rows", n)
			}
		}
	}
}

func (r *Runner) runRecovered(ctx context.Context, job Job) (n int64, ran bool, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("panic: %v", p)
			// RunOnce never got to record this run.
			r.Stats.record(job.Name, 0, true, err, r.Now())
		}
	}()
	return r.RunOnce(ctx, job)
}

// RunOnce runs one job immediately if the advisory lock is free, and reports
// the rows affected and whether it ran.
func (r *Runner) RunOnce(ctx context.Context, job Job) (int64, bool, error) {
	var n int64
	ran, err := r.Store.WithAdvisoryLock(ctx, job.LockID, func(q *store.Queries) error {
		var err error
		n, err = job.Run(ctx, q, r.Now())
		return err
	})
	r.Stats.record(job.Name, n, ran, err, r.Now())
	return n, ran, err
}
