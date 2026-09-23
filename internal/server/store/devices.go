package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const deviceCols = `id, hostname, serial, smbios_uuid, os_version, status, cert_serial, cert_expires_at, last_seen_at, agent_version, enrolled_at, replaced_by, prev_cert_serial, os_build, manufacturer, model`

func scanDevice(row pgx.Row) (Device, error) {
	var d Device
	err := row.Scan(&d.ID, &d.Hostname, &d.Serial, &d.SMBIOSUUID, &d.OSVersion, &d.Status, &d.CertSerial,
		&d.CertExpiresAt, &d.LastSeenAt, &d.AgentVersion, &d.EnrolledAt, &d.ReplacedBy,
		&d.PrevCertSerial, &d.OSBuild, &d.Manufacturer, &d.Model)
	return d, notFound(err)
}

func (q *Queries) CreateDevice(ctx context.Context, d Device) error {
	_, err := q.db.Exec(ctx, `
		INSERT INTO devices (id, tenant_id, hostname, serial, smbios_uuid, os_version, status, cert_serial, cert_expires_at, enrolled_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		d.ID, DefaultTenantID, d.Hostname, d.Serial, d.SMBIOSUUID, d.OSVersion, d.Status, d.CertSerial, d.CertExpiresAt, d.EnrolledAt)
	return err
}

func (q *Queries) GetDevice(ctx context.Context, tenantID, id uuid.UUID) (Device, error) {
	return scanDevice(q.db.QueryRow(ctx,
		`SELECT `+deviceCols+` FROM devices WHERE tenant_id = $1 AND id = $2`, tenantID, id))
}

// FindActiveDeviceByHardware finds an active device with the same non-empty
// SMBIOS UUID or serial number (used to detect reimaged machines).
func (q *Queries) FindActiveDeviceByHardware(ctx context.Context, tenantID uuid.UUID, serial, smbiosUUID string) (Device, error) {
	if serial == "" && smbiosUUID == "" {
		return Device{}, ErrNotFound
	}
	return scanDevice(q.db.QueryRow(ctx, `
		SELECT `+deviceCols+` FROM devices
		WHERE tenant_id = $1 AND status = 'active'
		  AND ((smbios_uuid <> '' AND smbios_uuid = $2) OR (serial <> '' AND serial = $3))
		ORDER BY enrolled_at DESC
		LIMIT 1`, tenantID, smbiosUUID, serial))
}

func (q *Queries) MarkDeviceReplaced(ctx context.Context, tenantID, oldID, newID uuid.UUID) error {
	_, err := q.db.Exec(ctx,
		`UPDATE devices SET status = 'replaced', replaced_by = $3 WHERE tenant_id = $1 AND id = $2`,
		tenantID, oldID, newID)
	return err
}

func (q *Queries) SetDeviceStatus(ctx context.Context, tenantID, id uuid.UUID, status string) error {
	_, err := q.db.Exec(ctx,
		`UPDATE devices SET status = $3 WHERE tenant_id = $1 AND id = $2`, tenantID, id, status)
	return err
}

func (q *Queries) RecordCheckin(ctx context.Context, tenantID, id uuid.UUID, agentVersion string, at time.Time) error {
	_, err := q.db.Exec(ctx,
		`UPDATE devices SET last_seen_at = $3, agent_version = $4 WHERE tenant_id = $1 AND id = $2`,
		tenantID, id, at, agentVersion)
	return err
}

// ListDevices returns every device, ordered by hostname.
func (q *Queries) ListDevices(ctx context.Context) ([]Device, error) {
	rows, err := q.db.Query(ctx, `SELECT `+deviceCols+` FROM devices WHERE tenant_id = $1 ORDER BY lower(hostname), enrolled_at`,
		DefaultTenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Device
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// DeviceBucketCounts returns the dashboard's three FleetBar buckets - active,
// stale and retired - computed in one aggregate query over the whole fleet
// rather than by pulling every device's row into Go: retired is anything not
// active, stale is active with no check-in since cutoff (or none on record),
// and active is active with a check-in at or after cutoff. The caller passes
// cutoff (now minus the console's StaleAfter window) so this stays the same
// "how long since last seen" definition the device list's own Stale flag
// uses, rather than a second copy of the threshold living in SQL. The three
// always partition every device, so their sum is the total device count.
func (q *Queries) DeviceBucketCounts(ctx context.Context, cutoff time.Time, scope DeviceScope) (active, stale, retired int, err error) {
	err = q.db.QueryRow(ctx, `
		SELECT
			count(*) FILTER (WHERE status = $2 AND last_seen_at >= $3),
			count(*) FILTER (WHERE status = $2 AND (last_seen_at IS NULL OR last_seen_at < $3)),
			count(*) FILTER (WHERE status <> $2)
		FROM devices WHERE tenant_id = $1 AND `+scopeSQL("id", 4)+``, DefaultTenantID, DeviceActive, cutoff, scope.arg()).Scan(&active, &stale, &retired)
	return active, stale, retired, err
}

// ActiveAgentVersionCounts groups active devices by their reported agent
// version, for the dashboard's top-10 list. Unlike DeviceBucketCounts this
// does need one row per device, but only two narrow columns of it
// (agent_version here, os_build in ActiveOSBuildCounts) rather than the full
// device row ListDevices returns.
func (q *Queries) ActiveAgentVersionCounts(ctx context.Context, scope DeviceScope) (map[string]int, error) {
	rows, err := q.db.Query(ctx, `
		SELECT agent_version, count(*) FROM devices
		WHERE tenant_id = $1 AND status = $2 AND agent_version <> '' AND `+scopeSQL("id", 3)+`
		GROUP BY agent_version`, DefaultTenantID, DeviceActive, scope.arg())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var version string
		var n int
		if err := rows.Scan(&version, &n); err != nil {
			return nil, err
		}
		out[version] = n
	}
	return out, rows.Err()
}

// ActiveOSBuildCounts groups active devices by their reported OS build, for
// the dashboard's top-10 list. See ActiveAgentVersionCounts.
func (q *Queries) ActiveOSBuildCounts(ctx context.Context, scope DeviceScope) (map[string]int, error) {
	rows, err := q.db.Query(ctx, `
		SELECT os_build, count(*) FROM devices
		WHERE tenant_id = $1 AND status = $2 AND os_build <> '' AND `+scopeSQL("id", 3)+`
		GROUP BY os_build`, DefaultTenantID, DeviceActive, scope.arg())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var build string
		var n int
		if err := rows.Scan(&build, &n); err != nil {
			return nil, err
		}
		out[build] = n
	}
	return out, rows.Err()
}

// DayCount is one day's tally, for the dashboard's enrolment trend.
type DayCount struct {
	Day   time.Time
	Count int
}

// EnrollmentTrend counts devices enrolled per day from since onwards, oldest
// first. Days on which nothing enrolled are filled in as zero by
// generate_series rather than left out, because a sparkline that silently
// closes its gaps draws a slope that never happened.
//
// The days are UTC days, said explicitly rather than left to the session's
// timezone: the server, the database and the browser can each be somewhere
// different, and a bucket that depends on which one is asking is a bucket
// that moves a device into yesterday.
func (q *Queries) EnrollmentTrend(ctx context.Context, since time.Time, scope DeviceScope) ([]DayCount, error) {
	rows, err := q.db.Query(ctx, `
		SELECT d.day, count(v.id)
		FROM generate_series(
		         date_trunc('day', $2::timestamptz AT TIME ZONE 'UTC'),
		         date_trunc('day', now() AT TIME ZONE 'UTC'),
		         interval '1 day') AS d(day)
		LEFT JOIN devices v
		  ON v.tenant_id = $1 AND date_trunc('day', v.enrolled_at AT TIME ZONE 'UTC') = d.day AND `+scopeSQL("v.id", 3)+`
		GROUP BY d.day
		ORDER BY d.day`, DefaultTenantID, since, scope.arg())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DayCount
	for rows.Next() {
		var dc DayCount
		if err := rows.Scan(&dc.Day, &dc.Count); err != nil {
			return nil, err
		}
		out = append(out, dc)
	}
	return out, rows.Err()
}

// CheckInRecency buckets active devices by how long since their last check-in.
// The buckets are cumulative in intent but exclusive in fact - a device counted
// in "day" is one that checked in within a day but not within an hour - so they
// sum to the active fleet and can be drawn as one bar.
func (q *Queries) CheckInRecency(ctx context.Context, now time.Time, scope DeviceScope) (hour, day, week, older, never int, err error) {
	err = q.db.QueryRow(ctx, `
		SELECT
			count(*) FILTER (WHERE last_seen_at >= $3),
			count(*) FILTER (WHERE last_seen_at >= $4 AND last_seen_at < $3),
			count(*) FILTER (WHERE last_seen_at >= $5 AND last_seen_at < $4),
			count(*) FILTER (WHERE last_seen_at IS NOT NULL AND last_seen_at < $5),
			count(*) FILTER (WHERE last_seen_at IS NULL)
		FROM devices
		WHERE tenant_id = $1 AND status = $2 AND `+scopeSQL("id", 6)+``,
		DefaultTenantID, DeviceActive,
		now.Add(-time.Hour), now.Add(-24*time.Hour), now.Add(-7*24*time.Hour), scope.arg()).
		Scan(&hour, &day, &week, &older, &never)
	return hour, day, week, older, never, err
}

// UpdateDeviceHardware applies non-empty inventory values; empty values leave
// the existing column untouched.
func (q *Queries) UpdateDeviceHardware(ctx context.Context, tenantID, id uuid.UUID, h HardwareInfo) error {
	_, err := q.db.Exec(ctx, `
		UPDATE devices SET
			hostname     = COALESCE(NULLIF($3, ''), hostname),
			serial       = COALESCE(NULLIF($4, ''), serial),
			smbios_uuid  = COALESCE(NULLIF($5, ''), smbios_uuid),
			os_version   = COALESCE(NULLIF($6, ''), os_version),
			os_build     = COALESCE(NULLIF($7, ''), os_build),
			manufacturer = COALESCE(NULLIF($8, ''), manufacturer),
			model        = COALESCE(NULLIF($9, ''), model)
		WHERE tenant_id = $1 AND id = $2`,
		tenantID, id, h.Hostname, h.Serial, h.SMBIOSUUID, h.OSVersion, h.OSBuild, h.Manufacturer, h.Model)
	return err
}

// UpdateDeviceCert records a reissued certificate. prevSerial is the serial the
// renewal request authenticated with; it stays acceptable until the device uses
// the new certificate.
func (q *Queries) UpdateDeviceCert(ctx context.Context, tenantID, id uuid.UUID, prevSerial, newSerial string, expiresAt time.Time) error {
	_, err := q.db.Exec(ctx, `
		UPDATE devices SET prev_cert_serial = $3, cert_serial = $4, cert_expires_at = $5
		WHERE tenant_id = $1 AND id = $2`,
		tenantID, id, prevSerial, newSerial, expiresAt)
	return err
}

// ClearPrevCertSerial drops the superseded certificate serial.
func (q *Queries) ClearPrevCertSerial(ctx context.Context, tenantID, id uuid.UUID) error {
	_, err := q.db.Exec(ctx,
		`UPDATE devices SET prev_cert_serial = '' WHERE tenant_id = $1 AND id = $2`, tenantID, id)
	return err
}
