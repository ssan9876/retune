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
func (q *Queries) FindActiveDeviceByHardware(ctx context.Context, serial, smbiosUUID string) (Device, error) {
	if serial == "" && smbiosUUID == "" {
		return Device{}, ErrNotFound
	}
	return scanDevice(q.db.QueryRow(ctx, `
		SELECT `+deviceCols+` FROM devices
		WHERE status = 'active'
		  AND ((smbios_uuid <> '' AND smbios_uuid = $1) OR (serial <> '' AND serial = $2))
		ORDER BY enrolled_at DESC
		LIMIT 1`, smbiosUUID, serial))
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
	rows, err := q.db.Query(ctx, `SELECT `+deviceCols+` FROM devices ORDER BY lower(hostname), enrolled_at`)
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
