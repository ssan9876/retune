package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Command statuses.
const (
	CommandQueued    = "queued"
	CommandDelivered = "delivered"
	CommandRunning   = "running"
	CommandSucceeded = "succeeded"
	CommandFailed    = "failed"
	CommandTimedOut  = "timed_out"
	CommandExpired   = "expired"
)

// Command is one ad-hoc instruction for a device.
type Command struct {
	ID          uuid.UUID
	DeviceID    uuid.UUID
	Type        string
	Payload     []byte
	Status      string
	CreatedBy   string
	CreatedAt   time.Time
	DeliveredAt *time.Time
	StartedAt   *time.Time
	CompletedAt *time.Time
	ExpiresAt   time.Time
	// Hostname is filled by list queries that join devices. Single-command
	// lookups leave it empty because their callers already know the device.
	Hostname string
}

// CommandResult is what the agent reported for a command.
type CommandResult struct {
	CommandID       uuid.UUID
	ExitCode        int
	Stdout          string
	Stderr          string
	StdoutTruncated bool
	StderrTruncated bool
	Error           string
	StartedAt       time.Time
	FinishedAt      time.Time
}

const commandCols = `id, device_id, type, payload, status, created_by, created_at, delivered_at, started_at, completed_at, expires_at`

func scanCommand(row pgx.Row) (Command, error) {
	var c Command
	err := row.Scan(&c.ID, &c.DeviceID, &c.Type, &c.Payload, &c.Status, &c.CreatedBy, &c.CreatedAt,
		&c.DeliveredAt, &c.StartedAt, &c.CompletedAt, &c.ExpiresAt)
	return c, notFound(err)
}

func (q *Queries) queryCommands(ctx context.Context, sql string, args ...any) ([]Command, error) {
	rows, err := q.db.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Command
	for rows.Next() {
		c, err := scanCommand(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// HasQueuedCommand reports whether a device has a command waiting for it.
func (q *Queries) HasQueuedCommand(ctx context.Context, deviceID uuid.UUID) (bool, error) {
	var ok bool
	err := q.db.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM commands WHERE tenant_id = $1 AND device_id = $2 AND status = 'queued')`,
		DefaultTenantID, deviceID).Scan(&ok)
	return ok, err
}

func (q *Queries) CreateCommand(ctx context.Context, c Command) error {
	_, err := q.db.Exec(ctx, `
		INSERT INTO commands (id, tenant_id, device_id, type, payload, status, created_by, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		c.ID, DefaultTenantID, c.DeviceID, c.Type, c.Payload, c.Status, c.CreatedBy, c.CreatedAt, c.ExpiresAt)
	if err != nil {
		return err
	}
	// A device waiting between check-ins picks it up now, not at its next
	// check-in.
	return q.Wake(ctx, "device:"+c.DeviceID.String())
}

func (q *Queries) GetCommand(ctx context.Context, tenantID, id uuid.UUID) (Command, error) {
	return scanCommand(q.db.QueryRow(ctx,
		`SELECT `+commandCols+` FROM commands WHERE tenant_id = $1 AND id = $2`, tenantID, id))
}

// ExpireCommands marks undelivered and delivered commands past their TTL as
// expired. Running commands are left alone.
func (q *Queries) ExpireCommands(ctx context.Context, now time.Time) (int64, error) {
	tag, err := q.db.Exec(ctx, `
		UPDATE commands SET status = 'expired', completed_at = $1
		WHERE status IN ('queued', 'delivered') AND expires_at <= $1`, now)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// PendingCommands returns commands still owed to a device, oldest first.
func (q *Queries) PendingCommands(ctx context.Context, deviceID uuid.UUID) ([]Command, error) {
	return q.queryCommands(ctx, `
		SELECT `+commandCols+` FROM commands
		WHERE tenant_id = $1 AND device_id = $2 AND status IN ('queued', 'delivered', 'running')
		ORDER BY created_at, id`, DefaultTenantID, deviceID)
}

func (q *Queries) MarkCommandsDelivered(ctx context.Context, ids []uuid.UUID, at time.Time) error {
	if len(ids) == 0 {
		return nil
	}
	text := make([]string, len(ids))
	for i, id := range ids {
		text[i] = id.String()
	}
	_, err := q.db.Exec(ctx, `
		UPDATE commands SET status = 'delivered', delivered_at = $2
		WHERE tenant_id = $3 AND id = ANY($1::uuid[]) AND status = 'queued'`, text, at, DefaultTenantID)
	return err
}

// MarkCommandRunning reports whether the command moved to running.
func (q *Queries) MarkCommandRunning(ctx context.Context, tenantID, id, deviceID uuid.UUID, at time.Time) (bool, error) {
	tag, err := q.db.Exec(ctx, `
		UPDATE commands SET status = 'running', started_at = $4
		WHERE tenant_id = $1 AND id = $2 AND device_id = $3 AND status IN ('queued', 'delivered')`,
		tenantID, id, deviceID, at)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// CompleteCommand reports whether the command moved to a terminal status.
func (q *Queries) CompleteCommand(ctx context.Context, tenantID, id, deviceID uuid.UUID, status string, at time.Time) (bool, error) {
	tag, err := q.db.Exec(ctx, `
		UPDATE commands SET status = $4, completed_at = $5
		WHERE tenant_id = $1 AND id = $2 AND device_id = $3 AND status IN ('queued', 'delivered', 'running')`,
		tenantID, id, deviceID, status, at)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

func (q *Queries) InsertCommandResult(ctx context.Context, r CommandResult) error {
	_, err := q.db.Exec(ctx, `
		INSERT INTO command_results (command_id, tenant_id, exit_code, stdout, stderr, stdout_truncated, stderr_truncated, error, started_at, finished_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		r.CommandID, DefaultTenantID, r.ExitCode, r.Stdout, r.Stderr, r.StdoutTruncated, r.StderrTruncated, r.Error, r.StartedAt, r.FinishedAt)
	return err
}

func (q *Queries) GetCommandResult(ctx context.Context, tenantID, id uuid.UUID) (CommandResult, error) {
	var r CommandResult
	err := q.db.QueryRow(ctx, `
		SELECT command_id, exit_code, stdout, stderr, stdout_truncated, stderr_truncated, error, started_at, finished_at
		FROM command_results WHERE tenant_id = $1 AND command_id = $2`, tenantID, id).
		Scan(&r.CommandID, &r.ExitCode, &r.Stdout, &r.Stderr, &r.StdoutTruncated, &r.StderrTruncated, &r.Error, &r.StartedAt, &r.FinishedAt)
	return r, notFound(err)
}

// ListCommands returns a device's newest commands first.
func (q *Queries) ListCommands(ctx context.Context, deviceID uuid.UUID, limit int) ([]Command, error) {
	return q.queryCommands(ctx, `
		SELECT `+commandCols+` FROM commands WHERE tenant_id = $1 AND device_id = $2
		ORDER BY created_at DESC, id DESC LIMIT $3`, DefaultTenantID, deviceID, limit)
}
