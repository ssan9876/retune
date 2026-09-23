package sweeper

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"retune/internal/server/store"
)

// AuditSink is somewhere outside Retune the audit log is copied to.
type AuditSink interface {
	// Name identifies the destination; it keys the destination's cursor, so
	// pointing a setting somewhere new starts that destination afresh.
	Name() string
	// Send delivers a batch, oldest first, or fails as a whole.
	Send(ctx context.Context, entries []store.AuditEntry) error
}

const (
	// auditStreamLag keeps the stream this far behind the present. An entry's
	// time is its transaction's start, so one that commits late can land
	// behind entries already sent; two minutes is far longer than any request
	// that writes to the audit log runs.
	auditStreamLag        = 2 * time.Minute
	auditStreamBatch      = 500
	auditStreamMaxBatches = 10
)

// AuditStreamJob copies new audit entries to each sink, at least once and in
// order. A sink seen for the first time starts from now: history is what the
// CSV export is for. A sink that fails is retried from the same place on the
// next run, without holding up the others.
func AuditStreamJob(sinks ...AuditSink) Job {
	return Job{
		Name: "audit.stream", LockID: lockAuditStream, Interval: 30 * time.Second,
		Run: func(ctx context.Context, q *store.Queries, now time.Time) (int64, error) {
			before := now.Add(-auditStreamLag)
			var sent int64
			var errs []error
			for _, s := range sinks {
				n, err := streamAudit(ctx, q, s, before, now)
				sent += n
				if err != nil {
					errs = append(errs, fmt.Errorf("%s: %w", s.Name(), err))
				}
			}
			return sent, errors.Join(errs...)
		},
	}
}

func streamAudit(ctx context.Context, q *store.Queries, s AuditSink, before, now time.Time) (int64, error) {
	c, ok, err := q.GetAuditCursor(ctx, s.Name())
	if err != nil {
		return 0, err
	}
	if !ok {
		return 0, q.SetAuditCursor(ctx, s.Name(), store.AuditCursor{LastAt: before, LastID: uuid.Nil}, now)
	}
	var sent int64
	for i := 0; i < auditStreamMaxBatches; i++ {
		entries, err := q.AuditAfter(ctx, c, before, auditStreamBatch)
		if err != nil || len(entries) == 0 {
			return sent, err
		}
		if err := s.Send(ctx, entries); err != nil {
			return sent, err
		}
		last := entries[len(entries)-1]
		c = store.AuditCursor{LastAt: last.At, LastID: last.ID}
		if err := q.SetAuditCursor(ctx, s.Name(), c, now); err != nil {
			return sent, err
		}
		sent += int64(len(entries))
		if len(entries) < auditStreamBatch {
			break
		}
	}
	return sent, nil
}
