package store

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// BitLockerKey is one escrowed recovery password, held encrypted.
type BitLockerKey struct {
	ID       uuid.UUID
	DeviceID uuid.UUID
	// Hostname is filled in by the listing queries only.
	Hostname   string
	VolumeID   string
	Method     string
	Ciphertext []byte
	Nonce      []byte
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// UpsertBitLockerKey stores an escrowed key, replacing an earlier one for the
// same volume: a volume that has been re-encrypted has a new recovery password
// and the old one is useless.
func (q *Queries) UpsertBitLockerKey(ctx context.Context, k BitLockerKey) error {
	_, err := q.db.Exec(ctx, `
		INSERT INTO bitlocker_keys (id, tenant_id, device_id, volume_id, method, ciphertext, nonce, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8)
		ON CONFLICT (device_id, volume_id) DO UPDATE
		SET method = EXCLUDED.method, ciphertext = EXCLUDED.ciphertext,
		    nonce = EXCLUDED.nonce, updated_at = EXCLUDED.updated_at`,
		k.ID, DefaultTenantID, k.DeviceID, k.VolumeID, k.Method, k.Ciphertext, k.Nonce, k.CreatedAt)
	return err
}

// GetBitLockerKey returns one escrowed key, including its ciphertext.
func (q *Queries) GetBitLockerKey(ctx context.Context, tenantID, id uuid.UUID) (BitLockerKey, error) {
	var k BitLockerKey
	err := q.db.QueryRow(ctx, `
		SELECT k.id, k.device_id, d.hostname, k.volume_id, k.method, k.ciphertext, k.nonce, k.created_at, k.updated_at
		FROM bitlocker_keys k
		JOIN devices d ON d.id = k.device_id
		WHERE k.tenant_id = $1 AND k.id = $2`, tenantID, id).
		Scan(&k.ID, &k.DeviceID, &k.Hostname, &k.VolumeID, &k.Method, &k.Ciphertext, &k.Nonce, &k.CreatedAt, &k.UpdatedAt)
	return k, notFound(err)
}

// HasBitLockerKey reports whether a volume's key is already escrowed, which is
// what lets an agent know it has nothing more to do.
func (q *Queries) HasBitLockerKey(ctx context.Context, deviceID uuid.UUID, volumeID string) (bool, error) {
	var ok bool
	err := q.db.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM bitlocker_keys WHERE device_id = $1 AND volume_id = $2)`,
		deviceID, volumeID).Scan(&ok)
	return ok, err
}

// ListBitLockerKeys returns the escrowed volumes of one device. It deliberately
// does not return the ciphertext: listing keys should never hand them out.
func (q *Queries) ListBitLockerKeys(ctx context.Context, deviceID uuid.UUID) ([]BitLockerKey, error) {
	rows, err := q.db.Query(ctx, `
		SELECT k.id, k.device_id, d.hostname, k.volume_id, k.method, k.created_at, k.updated_at
		FROM bitlocker_keys k
		JOIN devices d ON d.id = k.device_id
		WHERE k.tenant_id = $1 AND k.device_id = $2
		ORDER BY k.volume_id`, DefaultTenantID, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BitLockerKey
	for rows.Next() {
		var k BitLockerKey
		if err := rows.Scan(&k.ID, &k.DeviceID, &k.Hostname, &k.VolumeID, &k.Method,
			&k.CreatedAt, &k.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}
