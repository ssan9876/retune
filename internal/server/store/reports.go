package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Report kinds.
const (
	ReportDevices    = "devices"
	ReportCompliance = "compliance"
)

// ScheduledReport is a CSV export emailed on a schedule.
type ScheduledReport struct {
	ID         uuid.UUID
	Name       string
	Kind       string
	PolicyID   *uuid.UUID
	State      string
	Recipients []string
	Frequency  string
	Weekday    int
	Hour       int
	Timezone   string
	Enabled    bool
	NextRunAt  time.Time
	LastSentAt *time.Time
	LastError  string
	CreatedAt  time.Time
	UpdatedAt  time.Time
	CreatedBy  string
}

const reportCols = `id, name, kind, policy_id, state, recipients, frequency, weekday, hour, timezone,
	enabled, next_run_at, last_sent_at, last_error, created_at, updated_at, created_by`

func scanReport(row pgx.Row) (ScheduledReport, error) {
	var r ScheduledReport
	err := row.Scan(&r.ID, &r.Name, &r.Kind, &r.PolicyID, &r.State, &r.Recipients, &r.Frequency, &r.Weekday,
		&r.Hour, &r.Timezone, &r.Enabled, &r.NextRunAt, &r.LastSentAt, &r.LastError, &r.CreatedAt, &r.UpdatedAt, &r.CreatedBy)
	return r, notFound(err)
}

// CreateReport stores a report; a name already taken is ErrDuplicate.
func (q *Queries) CreateReport(ctx context.Context, r ScheduledReport) error {
	_, err := q.db.Exec(ctx, `
		INSERT INTO scheduled_reports (id, tenant_id, name, kind, policy_id, state, recipients, frequency, weekday,
		                               hour, timezone, enabled, next_run_at, created_at, updated_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $14, $15)`,
		r.ID, DefaultTenantID, r.Name, r.Kind, r.PolicyID, r.State, r.Recipients, r.Frequency, r.Weekday,
		r.Hour, r.Timezone, r.Enabled, r.NextRunAt, r.CreatedAt, r.CreatedBy)
	return duplicate(err)
}

// UpdateReport replaces a report's definition and its next run.
func (q *Queries) UpdateReport(ctx context.Context, r ScheduledReport) error {
	tag, err := q.db.Exec(ctx, `
		UPDATE scheduled_reports SET name = $3, kind = $4, policy_id = $5, state = $6, recipients = $7,
		       frequency = $8, weekday = $9, hour = $10, timezone = $11, enabled = $12, next_run_at = $13, updated_at = $14
		WHERE tenant_id = $1 AND id = $2`,
		DefaultTenantID, r.ID, r.Name, r.Kind, r.PolicyID, r.State, r.Recipients, r.Frequency, r.Weekday,
		r.Hour, r.Timezone, r.Enabled, r.NextRunAt, r.UpdatedAt)
	if err != nil {
		return duplicate(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// GetReport looks up one report.
func (q *Queries) GetReport(ctx context.Context, id uuid.UUID) (ScheduledReport, error) {
	return scanReport(q.db.QueryRow(ctx,
		`SELECT `+reportCols+` FROM scheduled_reports WHERE tenant_id = $1 AND id = $2`, DefaultTenantID, id))
}

// ListReports returns every report by name.
func (q *Queries) ListReports(ctx context.Context) ([]ScheduledReport, error) {
	return q.reports(ctx, `SELECT `+reportCols+` FROM scheduled_reports WHERE tenant_id = $1 ORDER BY lower(name)`, DefaultTenantID)
}

// DueReports claims the enabled reports due at now, locking them so a second
// replica skips rather than sends them twice.
func (q *Queries) DueReports(ctx context.Context, now time.Time) ([]ScheduledReport, error) {
	return q.reports(ctx, `
		SELECT `+reportCols+` FROM scheduled_reports
		WHERE tenant_id = $1 AND enabled AND next_run_at <= $2
		ORDER BY next_run_at FOR UPDATE SKIP LOCKED`, DefaultTenantID, now)
}

func (q *Queries) reports(ctx context.Context, sql string, args ...any) ([]ScheduledReport, error) {
	rows, err := q.db.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ScheduledReport
	for rows.Next() {
		r, err := scanReport(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// RecordReportRun notes a send attempt: when the next is due, and the error,
// or when it last succeeded.
func (q *Queries) RecordReportRun(ctx context.Context, id uuid.UUID, next time.Time, sentAt *time.Time, lastError string) error {
	_, err := q.db.Exec(ctx, `
		UPDATE scheduled_reports SET next_run_at = $3, last_sent_at = coalesce($4, last_sent_at), last_error = $5
		WHERE tenant_id = $1 AND id = $2`, DefaultTenantID, id, next, sentAt, lastError)
	return err
}

// DeleteReport removes a report.
func (q *Queries) DeleteReport(ctx context.Context, id uuid.UUID) error {
	tag, err := q.db.Exec(ctx, `DELETE FROM scheduled_reports WHERE tenant_id = $1 AND id = $2`, DefaultTenantID, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}
