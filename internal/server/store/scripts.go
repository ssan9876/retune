package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Script run statuses.
const (
	RunSucceeded = "succeeded"
	RunFailed    = "failed"
	RunTimedOut  = "timed_out"
)

// Phases a run can be decided in.
const (
	PhaseScript      = "script"
	PhaseDetection   = "detection"
	PhaseRemediation = "remediation"
)

// Script is one entry in the library. The body lives in its versions.
type Script struct {
	ID             uuid.UUID
	Name           string
	Description    string
	CurrentVersion int
	CreatedAt      time.Time
	UpdatedAt      time.Time
	CreatedBy      string
}

// ScriptVersion is an immutable snapshot of a script's contents.
type ScriptVersion struct {
	ScriptID      uuid.UUID
	Version       int
	Body          string
	DetectionBody string
	Hash          string
	CreatedAt     time.Time
	CreatedBy     string
}

// ScriptRun is one execution on one device.
type ScriptRun struct {
	ID       uuid.UUID
	ScriptID uuid.UUID
	Version  int
	DeviceID uuid.UUID
	// Hostname is filled in by the listing queries only.
	Hostname        string
	Status          string
	Phase           string
	Remediated      bool
	ExitCode        int
	Stdout          string
	Stderr          string
	StdoutTruncated bool
	StderrTruncated bool
	Error           string
	StartedAt       time.Time
	FinishedAt      time.Time
}

const scriptCols = `id, name, description, current_version, created_at, updated_at, created_by`

func scanScript(row pgx.Row) (Script, error) {
	var s Script
	err := row.Scan(&s.ID, &s.Name, &s.Description, &s.CurrentVersion, &s.CreatedAt, &s.UpdatedAt, &s.CreatedBy)
	return s, notFound(err)
}

func (q *Queries) CreateScript(ctx context.Context, s Script) error {
	_, err := q.db.Exec(ctx, `
		INSERT INTO scripts (id, tenant_id, name, description, current_version, created_at, updated_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $6, $7)`,
		s.ID, DefaultTenantID, s.Name, s.Description, s.CurrentVersion, s.CreatedAt, s.CreatedBy)
	return err
}

func (q *Queries) GetScript(ctx context.Context, id uuid.UUID) (Script, error) {
	return scanScript(q.db.QueryRow(ctx, `SELECT `+scriptCols+` FROM scripts WHERE id = $1`, id))
}

// GetScriptByName finds a script by its case-insensitive name.
func (q *Queries) GetScriptByName(ctx context.Context, name string) (Script, error) {
	return scanScript(q.db.QueryRow(ctx,
		`SELECT `+scriptCols+` FROM scripts WHERE tenant_id = $1 AND lower(name) = lower($2)`,
		DefaultTenantID, name))
}

// ListScripts returns one page of the library.
func (q *Queries) ListScripts(ctx context.Context, page Page) ([]Script, int, error) {
	p := page.Normalized()
	rows, err := q.db.Query(ctx, `
		SELECT `+scriptCols+`, count(*) OVER () AS total FROM scripts
		WHERE tenant_id = $1
		ORDER BY lower(name)
		LIMIT $2 OFFSET $3`, DefaultTenantID, p.Limit, p.Offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []Script
	total := 0
	for rows.Next() {
		var s Script
		if err := rows.Scan(&s.ID, &s.Name, &s.Description, &s.CurrentVersion,
			&s.CreatedAt, &s.UpdatedAt, &s.CreatedBy, &total); err != nil {
			return nil, 0, err
		}
		out = append(out, s)
	}
	return out, total, rows.Err()
}

// UpdateScript stores the name, description and current version.
func (q *Queries) UpdateScript(ctx context.Context, s Script) error {
	_, err := q.db.Exec(ctx, `
		UPDATE scripts SET name = $2, description = $3, current_version = $4, updated_at = $5
		WHERE id = $1`, s.ID, s.Name, s.Description, s.CurrentVersion, s.UpdatedAt)
	return err
}

// DeleteScript removes a script and its versions. Its runs are kept.
func (q *Queries) DeleteScript(ctx context.Context, id uuid.UUID) error {
	_, err := q.db.Exec(ctx, `DELETE FROM scripts WHERE id = $1`, id)
	return err
}

func (q *Queries) CreateScriptVersion(ctx context.Context, v ScriptVersion) error {
	_, err := q.db.Exec(ctx, `
		INSERT INTO script_versions (script_id, version, tenant_id, body, detection_body, hash, created_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		v.ScriptID, v.Version, DefaultTenantID, v.Body, v.DetectionBody, v.Hash, v.CreatedAt, v.CreatedBy)
	return err
}

func (q *Queries) GetScriptVersion(ctx context.Context, scriptID uuid.UUID, version int) (ScriptVersion, error) {
	var v ScriptVersion
	err := q.db.QueryRow(ctx, `
		SELECT script_id, version, body, detection_body, hash, created_at, created_by
		FROM script_versions WHERE script_id = $1 AND version = $2`, scriptID, version).
		Scan(&v.ScriptID, &v.Version, &v.Body, &v.DetectionBody, &v.Hash, &v.CreatedAt, &v.CreatedBy)
	return v, notFound(err)
}

// ListScriptVersions returns a script's versions, newest first.
func (q *Queries) ListScriptVersions(ctx context.Context, scriptID uuid.UUID) ([]ScriptVersion, error) {
	rows, err := q.db.Query(ctx, `
		SELECT script_id, version, body, detection_body, hash, created_at, created_by
		FROM script_versions WHERE script_id = $1 ORDER BY version DESC`, scriptID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ScriptVersion
	for rows.Next() {
		var v ScriptVersion
		if err := rows.Scan(&v.ScriptID, &v.Version, &v.Body, &v.DetectionBody,
			&v.Hash, &v.CreatedAt, &v.CreatedBy); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (q *Queries) InsertScriptRun(ctx context.Context, r ScriptRun) error {
	_, err := q.db.Exec(ctx, `
		INSERT INTO script_runs (id, tenant_id, script_id, version, device_id, status, phase, remediated,
		                         exit_code, stdout, stderr, stdout_truncated, stderr_truncated, error,
		                         started_at, finished_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`,
		r.ID, DefaultTenantID, r.ScriptID, r.Version, r.DeviceID, r.Status, r.Phase, r.Remediated,
		r.ExitCode, r.Stdout, r.Stderr, r.StdoutTruncated, r.StderrTruncated, r.Error,
		r.StartedAt, r.FinishedAt)
	return err
}

const runCols = `r.id, r.script_id, r.version, r.device_id, r.status, r.phase, r.remediated,
	r.exit_code, r.stdout, r.stderr, r.stdout_truncated, r.stderr_truncated, r.error,
	r.started_at, r.finished_at`

func scanRun(rows pgx.Rows, r *ScriptRun, extra ...any) error {
	dest := []any{&r.ID, &r.ScriptID, &r.Version, &r.DeviceID, &r.Status, &r.Phase, &r.Remediated,
		&r.ExitCode, &r.Stdout, &r.Stderr, &r.StdoutTruncated, &r.StderrTruncated, &r.Error,
		&r.StartedAt, &r.FinishedAt}
	return rows.Scan(append(dest, extra...)...)
}

// ListScriptRuns returns one page of a script's runs, newest first, optionally
// for one device.
func (q *Queries) ListScriptRuns(ctx context.Context, scriptID uuid.UUID, deviceID *uuid.UUID, page Page) ([]ScriptRun, int, error) {
	p := page.Normalized()
	rows, err := q.db.Query(ctx, `
		SELECT `+runCols+`, d.hostname, count(*) OVER () AS total
		FROM script_runs r
		JOIN devices d ON d.id = r.device_id
		WHERE r.tenant_id = $1 AND r.script_id = $2
		  AND ($3::uuid IS NULL OR r.device_id = $3)
		-- The id breaks ties: two runs can share a timestamp, and UUIDv7 sorts
		-- by creation time, so the newer row still comes first.
		ORDER BY r.started_at DESC, r.id DESC
		LIMIT $4 OFFSET $5`, DefaultTenantID, scriptID, deviceID, p.Limit, p.Offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []ScriptRun
	total := 0
	for rows.Next() {
		var r ScriptRun
		if err := scanRun(rows, &r, &r.Hostname, &total); err != nil {
			return nil, 0, err
		}
		out = append(out, r)
	}
	return out, total, rows.Err()
}

// DeviceHasItem reports whether an item is assigned to a device, so the agent
// API can refuse to hand out a script the caller was not given.
func (q *Queries) DeviceHasItem(ctx context.Context, deviceID uuid.UUID, kind string, itemID uuid.UUID) (bool, error) {
	var ok bool
	err := q.db.QueryRow(ctx, `
		SELECT EXISTS (
		    SELECT 1 FROM assignments a
		    JOIN group_members gm ON gm.group_id = a.group_id AND gm.device_id = $1
		    WHERE a.mode = 'include' AND a.item_kind = $2 AND a.item_id = $3
		      AND NOT EXISTS (
		          SELECT 1 FROM assignments x
		          JOIN group_members gx ON gx.group_id = x.group_id AND gx.device_id = $1
		          WHERE x.mode = 'exclude' AND x.item_kind = $2 AND x.item_id = $3))`,
		deviceID, kind, itemID).Scan(&ok)
	return ok, err
}
