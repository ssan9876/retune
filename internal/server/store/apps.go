package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// App install statuses.
const (
	AppInstallSucceeded = "succeeded"
	AppInstallFailed    = "failed"
)

// App is one entry in the library. The winget package it deploys lives in
// its versions.
type App struct {
	ID             uuid.UUID
	Name           string
	Description    string
	CurrentVersion int
	CreatedAt      time.Time
	UpdatedAt      time.Time
	CreatedBy      string
}

// AppVersion is an immutable snapshot of what an app install asks for.
type AppVersion struct {
	AppID         uuid.UUID
	Version       int
	PackageID     string
	PinnedVersion string
	Scope         string
	InstallArgs   string
	Hash          string
	CreatedAt     time.Time
	CreatedBy     string
}

// AppInstall is one install or uninstall attempt on one device.
type AppInstall struct {
	ID       uuid.UUID
	AppID    uuid.UUID
	Version  int
	DeviceID uuid.UUID
	// Hostname is filled in by the listing queries only.
	Hostname string
	Intent   string
	Status   string
	// InstalledVersion is what winget reports afterwards.
	InstalledVersion string
	ExitCode         int
	Stdout           string
	Stderr           string
	StdoutTruncated  bool
	StderrTruncated  bool
	Error            string
	Detail           string
	StartedAt        time.Time
	FinishedAt       time.Time
}

const appCols = `id, name, description, current_version, created_at, updated_at, created_by`

func scanApp(row pgx.Row) (App, error) {
	var a App
	err := row.Scan(&a.ID, &a.Name, &a.Description, &a.CurrentVersion, &a.CreatedAt, &a.UpdatedAt, &a.CreatedBy)
	return a, notFound(err)
}

// CreateApp adds an app to the library.
func (q *Queries) CreateApp(ctx context.Context, a App) error {
	_, err := q.db.Exec(ctx, `
		INSERT INTO apps (id, tenant_id, name, description, current_version, created_at, updated_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $6, $7)`,
		a.ID, DefaultTenantID, a.Name, a.Description, a.CurrentVersion, a.CreatedAt, a.CreatedBy)
	return err
}

func (q *Queries) GetApp(ctx context.Context, id uuid.UUID) (App, error) {
	return scanApp(q.db.QueryRow(ctx, `SELECT `+appCols+` FROM apps WHERE id = $1`, id))
}

// GetAppByName finds an app by its case-insensitive name.
func (q *Queries) GetAppByName(ctx context.Context, name string) (App, error) {
	return scanApp(q.db.QueryRow(ctx,
		`SELECT `+appCols+` FROM apps WHERE tenant_id = $1 AND lower(name) = lower($2)`,
		DefaultTenantID, name))
}

// ListApps returns one page of the library.
func (q *Queries) ListApps(ctx context.Context, page Page) ([]App, int, error) {
	p := page.Normalized()
	rows, err := q.db.Query(ctx, `
		SELECT `+appCols+`, count(*) OVER () AS total FROM apps
		WHERE tenant_id = $1
		ORDER BY lower(name)
		LIMIT $2 OFFSET $3`, DefaultTenantID, p.Limit, p.Offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []App
	total := 0
	for rows.Next() {
		var a App
		if err := rows.Scan(&a.ID, &a.Name, &a.Description, &a.CurrentVersion,
			&a.CreatedAt, &a.UpdatedAt, &a.CreatedBy, &total); err != nil {
			return nil, 0, err
		}
		out = append(out, a)
	}
	return out, total, rows.Err()
}

// UpdateApp stores the name, description and current version.
func (q *Queries) UpdateApp(ctx context.Context, a App) error {
	_, err := q.db.Exec(ctx, `
		UPDATE apps SET name = $2, description = $3, current_version = $4, updated_at = $5
		WHERE id = $1`, a.ID, a.Name, a.Description, a.CurrentVersion, a.UpdatedAt)
	return err
}

// DeleteApp removes an app and its versions. Its installs are kept.
func (q *Queries) DeleteApp(ctx context.Context, id uuid.UUID) error {
	_, err := q.db.Exec(ctx, `DELETE FROM apps WHERE id = $1`, id)
	return err
}

func (q *Queries) CreateAppVersion(ctx context.Context, v AppVersion) error {
	_, err := q.db.Exec(ctx, `
		INSERT INTO app_versions (app_id, version, tenant_id, package_id, pinned_version, scope, install_args, hash, created_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		v.AppID, v.Version, DefaultTenantID, v.PackageID, v.PinnedVersion, v.Scope, v.InstallArgs, v.Hash, v.CreatedAt, v.CreatedBy)
	return err
}

func (q *Queries) GetAppVersion(ctx context.Context, appID uuid.UUID, version int) (AppVersion, error) {
	var v AppVersion
	err := q.db.QueryRow(ctx, `
		SELECT app_id, version, package_id, pinned_version, scope, install_args, hash, created_at, created_by
		FROM app_versions WHERE app_id = $1 AND version = $2`, appID, version).
		Scan(&v.AppID, &v.Version, &v.PackageID, &v.PinnedVersion, &v.Scope, &v.InstallArgs, &v.Hash, &v.CreatedAt, &v.CreatedBy)
	return v, notFound(err)
}

// ListAppVersions returns an app's versions, newest first.
func (q *Queries) ListAppVersions(ctx context.Context, appID uuid.UUID) ([]AppVersion, error) {
	rows, err := q.db.Query(ctx, `
		SELECT app_id, version, package_id, pinned_version, scope, install_args, hash, created_at, created_by
		FROM app_versions WHERE app_id = $1 ORDER BY version DESC`, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AppVersion
	for rows.Next() {
		var v AppVersion
		if err := rows.Scan(&v.AppID, &v.Version, &v.PackageID, &v.PinnedVersion,
			&v.Scope, &v.InstallArgs, &v.Hash, &v.CreatedAt, &v.CreatedBy); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (q *Queries) InsertAppInstall(ctx context.Context, in AppInstall) error {
	_, err := q.db.Exec(ctx, `
		INSERT INTO app_installs (id, tenant_id, app_id, version, device_id, intent, status, installed_version,
		                          exit_code, stdout, stderr, stdout_truncated, stderr_truncated, error, detail,
		                          started_at, finished_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)`,
		in.ID, DefaultTenantID, in.AppID, in.Version, in.DeviceID, in.Intent, in.Status, in.InstalledVersion,
		in.ExitCode, in.Stdout, in.Stderr, in.StdoutTruncated, in.StderrTruncated, in.Error, in.Detail,
		in.StartedAt, in.FinishedAt)
	return err
}

const appInstallCols = `i.id, i.app_id, i.version, i.device_id, i.intent, i.status, i.installed_version,
	i.exit_code, i.stdout, i.stderr, i.stdout_truncated, i.stderr_truncated, i.error, i.detail,
	i.started_at, i.finished_at`

func scanAppInstall(rows pgx.Rows, in *AppInstall, extra ...any) error {
	dest := []any{&in.ID, &in.AppID, &in.Version, &in.DeviceID, &in.Intent, &in.Status, &in.InstalledVersion,
		&in.ExitCode, &in.Stdout, &in.Stderr, &in.StdoutTruncated, &in.StderrTruncated, &in.Error, &in.Detail,
		&in.StartedAt, &in.FinishedAt}
	return rows.Scan(append(dest, extra...)...)
}

// ListAppInstalls returns one page of an app's install history, newest first,
// optionally for one device.
func (q *Queries) ListAppInstalls(ctx context.Context, appID uuid.UUID, deviceID *uuid.UUID, page Page) ([]AppInstall, int, error) {
	p := page.Normalized()
	rows, err := q.db.Query(ctx, `
		SELECT `+appInstallCols+`, d.hostname, count(*) OVER () AS total
		FROM app_installs i
		JOIN devices d ON d.id = i.device_id
		WHERE i.tenant_id = $1 AND i.app_id = $2
		  AND ($3::uuid IS NULL OR i.device_id = $3)
		-- The id breaks ties: two installs can share a timestamp, and UUIDv7
		-- sorts by creation time, so the newer row still comes first.
		ORDER BY i.started_at DESC, i.id DESC
		LIMIT $4 OFFSET $5`, DefaultTenantID, appID, deviceID, p.Limit, p.Offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []AppInstall
	total := 0
	for rows.Next() {
		var in AppInstall
		if err := scanAppInstall(rows, &in, &in.Hostname, &total); err != nil {
			return nil, 0, err
		}
		out = append(out, in)
	}
	return out, total, rows.Err()
}
