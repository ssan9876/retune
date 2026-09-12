package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// DeviceInventory is the latest inventory document for a device.
type DeviceInventory struct {
	DeviceID     uuid.UUID
	CollectedAt  time.Time
	ReceivedAt   time.Time
	Hash         string
	SoftwareHash string
	Data         []byte
	RAMGB        float64
	DiskFreeGB   float64
}

// Software is one installed package.
type Software struct {
	Name        string
	Version     string
	Publisher   string
	InstallDate string
	Scope       string
}

// HardwareInfo carries the device columns refreshed from inventory.
type HardwareInfo struct {
	Hostname     string
	Serial       string
	SMBIOSUUID   string
	OSVersion    string
	OSBuild      string
	Manufacturer string
	Model        string
}

func (q *Queries) GetInventory(ctx context.Context, deviceID uuid.UUID) (DeviceInventory, error) {
	var inv DeviceInventory
	err := q.db.QueryRow(ctx, `
		SELECT device_id, collected_at, received_at, hash, software_hash, data, ram_gb, disk_free_gb
		FROM device_inventory WHERE device_id = $1`, deviceID).
		Scan(&inv.DeviceID, &inv.CollectedAt, &inv.ReceivedAt, &inv.Hash, &inv.SoftwareHash, &inv.Data, &inv.RAMGB, &inv.DiskFreeGB)
	return inv, notFound(err)
}

func (q *Queries) UpsertInventory(ctx context.Context, inv DeviceInventory) error {
	_, err := q.db.Exec(ctx, `
		INSERT INTO device_inventory (device_id, tenant_id, collected_at, received_at, hash, software_hash, data, ram_gb, disk_free_gb)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (device_id) DO UPDATE SET
			collected_at  = EXCLUDED.collected_at,
			received_at   = EXCLUDED.received_at,
			hash          = EXCLUDED.hash,
			software_hash = EXCLUDED.software_hash,
			data          = EXCLUDED.data,
			ram_gb        = EXCLUDED.ram_gb,
			disk_free_gb  = EXCLUDED.disk_free_gb`,
		inv.DeviceID, DefaultTenantID, inv.CollectedAt, inv.ReceivedAt, inv.Hash, inv.SoftwareHash, inv.Data, inv.RAMGB, inv.DiskFreeGB)
	return err
}

// ReplaceSoftware swaps a device's package list.
func (q *Queries) ReplaceSoftware(ctx context.Context, deviceID uuid.UUID, sw []Software) error {
	if _, err := q.db.Exec(ctx, `DELETE FROM device_software WHERE device_id = $1`, deviceID); err != nil {
		return err
	}
	if len(sw) == 0 {
		return nil
	}
	device := pgtype.UUID{Bytes: deviceID, Valid: true}
	tenant := pgtype.UUID{Bytes: DefaultTenantID, Valid: true}
	rows := make([][]any, 0, len(sw))
	for _, s := range sw {
		rows = append(rows, []any{device, tenant, s.Name, s.Version, s.Publisher, s.InstallDate, s.Scope})
	}
	_, err := q.db.CopyFrom(ctx,
		pgx.Identifier{"device_software"},
		[]string{"device_id", "tenant_id", "name", "version", "publisher", "install_date", "scope"},
		pgx.CopyFromRows(rows))
	return err
}

func (q *Queries) ListSoftware(ctx context.Context, deviceID uuid.UUID) ([]Software, error) {
	rows, err := q.db.Query(ctx, `
		SELECT name, version, publisher, install_date, scope FROM device_software
		WHERE device_id = $1 ORDER BY lower(name), version`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Software
	for rows.Next() {
		var s Software
		if err := rows.Scan(&s.Name, &s.Version, &s.Publisher, &s.InstallDate, &s.Scope); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
