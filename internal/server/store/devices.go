package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const deviceCols = `id, hostname, serial, smbios_uuid, os_version, status, cert_serial, cert_expires_at, last_seen_at, agent_version, enrolled_at, replaced_by`

func scanDevice(row pgx.Row) (Device, error) {
	var d Device
	err := row.Scan(&d.ID, &d.Hostname, &d.Serial, &d.SMBIOSUUID, &d.OSVersion, &d.Status, &d.CertSerial, &d.CertExpiresAt, &d.LastSeenAt, &d.AgentVersion, &d.EnrolledAt, &d.ReplacedBy)
	return d, notFound(err)
}

func (q *Queries) CreateDevice(ctx context.Context, d Device) error {
	_, err := q.db.Exec(ctx, `
		INSERT INTO devices (id, tenant_id, hostname, serial, smbios_uuid, os_version, status, cert_serial, cert_expires_at, enrolled_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		d.ID, DefaultTenantID, d.Hostname, d.Serial, d.SMBIOSUUID, d.OSVersion, d.Status, d.CertSerial, d.CertExpiresAt, d.EnrolledAt)
	return err
}

func (q *Queries) GetDevice(ctx context.Context, id uuid.UUID) (Device, error) {
	return scanDevice(q.db.QueryRow(ctx, `SELECT `+deviceCols+` FROM devices WHERE id = $1`, id))
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

func (q *Queries) MarkDeviceReplaced(ctx context.Context, oldID, newID uuid.UUID) error {
	_, err := q.db.Exec(ctx, `UPDATE devices SET status = 'replaced', replaced_by = $2 WHERE id = $1`, oldID, newID)
	return err
}

func (q *Queries) SetDeviceStatus(ctx context.Context, id uuid.UUID, status string) error {
	_, err := q.db.Exec(ctx, `UPDATE devices SET status = $2 WHERE id = $1`, id, status)
	return err
}

func (q *Queries) RecordCheckin(ctx context.Context, id uuid.UUID, agentVersion string, at time.Time) error {
	_, err := q.db.Exec(ctx, `UPDATE devices SET last_seen_at = $2, agent_version = $3 WHERE id = $1`, id, at, agentVersion)
	return err
}
