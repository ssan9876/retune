package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Per-setting statuses a device reports.
const (
	SettingCompliant  = "compliant"
	SettingRemediated = "remediated"
	SettingError      = "error"
	SettingConflict   = "conflict"
)

// Profile is a named, versioned statement about how a machine should be.
type Profile struct {
	ID             uuid.UUID
	Name           string
	Description    string
	CurrentVersion int
	CreatedAt      time.Time
	UpdatedAt      time.Time
	CreatedBy      string
}

// ProfileVersion is an immutable snapshot of a profile's settings.
type ProfileVersion struct {
	ProfileID uuid.UUID
	Version   int
	Settings  []byte
	Hash      string
	CreatedAt time.Time
	CreatedBy string
}

// SettingStatus is how one setting of one profile is faring on one device.
type SettingStatus struct {
	DeviceID uuid.UUID
	// Hostname is filled in by the listing queries only.
	Hostname  string
	ProfileID uuid.UUID
	Identity  string
	Version   int
	Status    string
	Detail    string
	UpdatedAt time.Time
}

const profileCols = `id, name, description, current_version, created_at, updated_at, created_by`

func scanProfile(row pgx.Row) (Profile, error) {
	var p Profile
	err := row.Scan(&p.ID, &p.Name, &p.Description, &p.CurrentVersion, &p.CreatedAt, &p.UpdatedAt, &p.CreatedBy)
	return p, notFound(err)
}

func (q *Queries) CreateProfile(ctx context.Context, p Profile) error {
	_, err := q.db.Exec(ctx, `
		INSERT INTO profiles (id, tenant_id, name, description, current_version, created_at, updated_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $6, $7)`,
		p.ID, DefaultTenantID, p.Name, p.Description, p.CurrentVersion, p.CreatedAt, p.CreatedBy)
	return err
}

func (q *Queries) GetProfile(ctx context.Context, tenantID, id uuid.UUID) (Profile, error) {
	return scanProfile(q.db.QueryRow(ctx,
		`SELECT `+profileCols+` FROM profiles WHERE tenant_id = $1 AND id = $2`, tenantID, id))
}

func (q *Queries) GetProfileByName(ctx context.Context, name string) (Profile, error) {
	return scanProfile(q.db.QueryRow(ctx,
		`SELECT `+profileCols+` FROM profiles WHERE tenant_id = $1 AND lower(name) = lower($2)`,
		DefaultTenantID, name))
}

func (q *Queries) ListProfiles(ctx context.Context, page Page) ([]Profile, int, error) {
	p := page.Normalized()
	rows, err := q.db.Query(ctx, `
		SELECT `+profileCols+`, count(*) OVER () AS total FROM profiles
		WHERE tenant_id = $1
		ORDER BY lower(name)
		LIMIT $2 OFFSET $3`, DefaultTenantID, p.Limit, p.Offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []Profile
	total := 0
	for rows.Next() {
		var pr Profile
		if err := rows.Scan(&pr.ID, &pr.Name, &pr.Description, &pr.CurrentVersion,
			&pr.CreatedAt, &pr.UpdatedAt, &pr.CreatedBy, &total); err != nil {
			return nil, 0, err
		}
		out = append(out, pr)
	}
	return out, total, rows.Err()
}

func (q *Queries) UpdateProfile(ctx context.Context, tenantID uuid.UUID, p Profile) error {
	_, err := q.db.Exec(ctx, `
		UPDATE profiles SET name = $3, description = $4, current_version = $5, updated_at = $6
		WHERE tenant_id = $1 AND id = $2`, tenantID, p.ID, p.Name, p.Description, p.CurrentVersion, p.UpdatedAt)
	return err
}

// DeleteProfile removes a profile and its versions. Reported statuses are kept.
func (q *Queries) DeleteProfile(ctx context.Context, tenantID, id uuid.UUID) error {
	_, err := q.db.Exec(ctx, `DELETE FROM profiles WHERE tenant_id = $1 AND id = $2`, tenantID, id)
	return err
}

func (q *Queries) CreateProfileVersion(ctx context.Context, v ProfileVersion) error {
	_, err := q.db.Exec(ctx, `
		INSERT INTO profile_versions (profile_id, version, tenant_id, settings, hash, created_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		v.ProfileID, v.Version, DefaultTenantID, v.Settings, v.Hash, v.CreatedAt, v.CreatedBy)
	return err
}

func (q *Queries) GetProfileVersion(ctx context.Context, tenantID, profileID uuid.UUID, version int) (ProfileVersion, error) {
	var v ProfileVersion
	err := q.db.QueryRow(ctx, `
		SELECT profile_id, version, settings, hash, created_at, created_by
		FROM profile_versions WHERE tenant_id = $1 AND profile_id = $2 AND version = $3`, tenantID, profileID, version).
		Scan(&v.ProfileID, &v.Version, &v.Settings, &v.Hash, &v.CreatedAt, &v.CreatedBy)
	return v, notFound(err)
}

func (q *Queries) ListProfileVersions(ctx context.Context, profileID uuid.UUID) ([]ProfileVersion, error) {
	rows, err := q.db.Query(ctx, `
		SELECT profile_id, version, settings, hash, created_at, created_by
		FROM profile_versions WHERE tenant_id = $1 AND profile_id = $2 ORDER BY version DESC`, DefaultTenantID, profileID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ProfileVersion
	for rows.Next() {
		var v ProfileVersion
		if err := rows.Scan(&v.ProfileID, &v.Version, &v.Settings, &v.Hash, &v.CreatedAt, &v.CreatedBy); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// SetSettingStatus records what a device found for one setting.
func (q *Queries) SetSettingStatus(ctx context.Context, s SettingStatus) error {
	_, err := q.db.Exec(ctx, `
		INSERT INTO profile_setting_status (device_id, tenant_id, profile_id, identity, version, status, detail, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (device_id, profile_id, identity) DO UPDATE
		SET version = EXCLUDED.version, status = EXCLUDED.status,
		    detail = EXCLUDED.detail, updated_at = EXCLUDED.updated_at`,
		s.DeviceID, DefaultTenantID, s.ProfileID, s.Identity, s.Version, s.Status, s.Detail, s.UpdatedAt)
	return err
}

// ClearSettingStatus removes the statuses of settings a device no longer
// reports, so a setting removed from a profile stops showing an old result.
func (q *Queries) ClearSettingStatus(ctx context.Context, deviceID, profileID uuid.UUID, keep []string) error {
	_, err := q.db.Exec(ctx, `
		DELETE FROM profile_setting_status
		WHERE tenant_id = $1 AND device_id = $2 AND profile_id = $3 AND NOT (identity = ANY($4::text[]))`,
		DefaultTenantID, deviceID, profileID, keep)
	return err
}

// ClearDeviceProfileStatus removes every setting status a device reported for
// one profile, used when the profile stops applying to it.
func (q *Queries) ClearDeviceProfileStatus(ctx context.Context, deviceID, profileID uuid.UUID) error {
	_, err := q.db.Exec(ctx,
		`DELETE FROM profile_setting_status WHERE tenant_id = $1 AND device_id = $2 AND profile_id = $3`,
		DefaultTenantID, deviceID, profileID)
	return err
}

// SettingStatusRollup counts settings by status for one profile.
func (q *Queries) SettingStatusRollup(ctx context.Context, profileID uuid.UUID, scope DeviceScope) (map[string]int, error) {
	rows, err := q.db.Query(ctx, `
		SELECT status, count(*) FROM profile_setting_status
		WHERE tenant_id = $1 AND profile_id = $2 AND `+scopeSQL("device_id", 3)+`
		GROUP BY status`, DefaultTenantID, profileID, scope.arg())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var status string
		var n int
		if err := rows.Scan(&status, &n); err != nil {
			return nil, err
		}
		out[status] = n
	}
	return out, rows.Err()
}

// ListSettingStatus returns one page of per-setting results for a profile,
// optionally narrowed to one status, so an administrator can go straight to
// what is failing.
func (q *Queries) ListSettingStatus(ctx context.Context, profileID uuid.UUID, status string, page Page, scope DeviceScope) ([]SettingStatus, int, error) {
	p := page.Normalized()
	rows, err := q.db.Query(ctx, `
		SELECT s.device_id, d.hostname, s.profile_id, s.identity, s.version, s.status, s.detail, s.updated_at,
		       count(*) OVER () AS total
		FROM profile_setting_status s
		JOIN devices d ON d.id = s.device_id
		WHERE s.tenant_id = $1 AND s.profile_id = $2
		  AND ($3 = '' OR s.status = $3) AND `+scopeSQL("s.device_id", 6)+`
		ORDER BY lower(d.hostname), s.identity
		LIMIT $4 OFFSET $5`, DefaultTenantID, profileID, status, p.Limit, p.Offset, scope.arg())
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []SettingStatus
	total := 0
	for rows.Next() {
		var s SettingStatus
		if err := rows.Scan(&s.DeviceID, &s.Hostname, &s.ProfileID, &s.Identity,
			&s.Version, &s.Status, &s.Detail, &s.UpdatedAt, &total); err != nil {
			return nil, 0, err
		}
		out = append(out, s)
	}
	return out, total, rows.Err()
}
