package store

import (
	"context"
	"time"
)

// The retention deletes each remove at most limit rows older than cutoff and
// report how many went. They delete by ctid from a LIMITed subquery, which is
// how Postgres spells "DELETE … LIMIT": the caller loops until a batch comes
// back short, so a first run over years of history is many small statements
// rather than one that locks a table and builds a transaction the size of it.

// DeleteAuditBefore removes audit entries older than cutoff.
func (q *Queries) DeleteAuditBefore(ctx context.Context, cutoff time.Time, limit int) (int64, error) {
	return q.execCount(ctx, `
		DELETE FROM audit_log WHERE ctid IN (
			SELECT ctid FROM audit_log WHERE tenant_id = $1 AND at < $2 LIMIT $3)`,
		DefaultTenantID, cutoff, limit)
}

// DeleteFinishedCommandsBefore removes commands that finished before cutoff,
// with their results. A command still queued, delivered or running is never
// removed, however old: it is state, not history. The result rows go in the
// same statement because command_results references commands with no
// cascade; the constraint is checked at the end of the statement, by which
// point both sides are gone.
func (q *Queries) DeleteFinishedCommandsBefore(ctx context.Context, cutoff time.Time, limit int) (int64, error) {
	return q.execCount(ctx, `
		WITH batch AS (
			SELECT id FROM commands
			WHERE tenant_id = $1 AND completed_at < $2
			  AND status IN ('succeeded', 'failed', 'timed_out', 'expired')
			LIMIT $3
		), results AS (
			DELETE FROM command_results WHERE command_id IN (SELECT id FROM batch)
		)
		DELETE FROM commands WHERE id IN (SELECT id FROM batch)`,
		DefaultTenantID, cutoff, limit)
}

// DeleteScriptRunsBefore removes script run history that finished before
// cutoff. Nothing reads a run as current state - rollups come from
// device_item_status and the agent schedules from its own records - so this
// only shortens the history the console can page through.
func (q *Queries) DeleteScriptRunsBefore(ctx context.Context, cutoff time.Time, limit int) (int64, error) {
	return q.execCount(ctx, `
		DELETE FROM script_runs WHERE ctid IN (
			SELECT ctid FROM script_runs WHERE tenant_id = $1 AND finished_at < $2 LIMIT $3)`,
		DefaultTenantID, cutoff, limit)
}

// DeleteAppInstallsBefore removes app install history that finished before
// cutoff, for the same reason and with the same guarantee as script runs.
func (q *Queries) DeleteAppInstallsBefore(ctx context.Context, cutoff time.Time, limit int) (int64, error) {
	return q.execCount(ctx, `
		DELETE FROM app_installs WHERE ctid IN (
			SELECT ctid FROM app_installs WHERE tenant_id = $1 AND finished_at < $2 LIMIT $3)`,
		DefaultTenantID, cutoff, limit)
}

func (q *Queries) execCount(ctx context.Context, sql string, args ...any) (int64, error) {
	tag, err := q.db.Exec(ctx, sql, args...)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// OutstandingCommandCounts counts commands not yet finished, by status, for
// the metrics endpoint. A queue that only grows is a fleet that stopped
// checking in, or a server that stopped handing work out.
func (q *Queries) OutstandingCommandCounts(ctx context.Context) (map[string]int, error) {
	return q.countBy(ctx, `
		SELECT status, count(*) FROM commands
		WHERE tenant_id = $1 AND status IN ('queued', 'delivered', 'running')
		GROUP BY status`, DefaultTenantID)
}

// FiringAlertCounts counts subjects currently firing, by rule kind, across
// enabled rules. A paused rule keeps its state current but tells nobody, so
// it is not an alert anyone is being sent.
func (q *Queries) FiringAlertCounts(ctx context.Context) (map[string]int, error) {
	return q.countBy(ctx, `
		SELECT r.kind, count(*) FROM alert_state s
		JOIN alert_rules r ON r.id = s.rule_id
		WHERE s.tenant_id = $1 AND r.enabled
		GROUP BY r.kind`, DefaultTenantID)
}

func (q *Queries) countBy(ctx context.Context, sql string, args ...any) (map[string]int, error) {
	rows, err := q.db.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var key string
		var n int
		if err := rows.Scan(&key, &n); err != nil {
			return nil, err
		}
		out[key] = n
	}
	return out, rows.Err()
}
