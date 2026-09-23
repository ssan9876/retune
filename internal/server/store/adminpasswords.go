package store

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Local admin password states.
const (
	AdminPasswordPending    = "pending"
	AdminPasswordActive     = "active"
	AdminPasswordSuperseded = "superseded"
	AdminPasswordAbandoned  = "abandoned"
)

// AdminPassword is one escrowed local administrator password. Listings leave
// the ciphertext out.
type AdminPassword struct {
	ID          uuid.UUID
	DeviceID    uuid.UUID
	Hostname    string
	Account     string
	Ciphertext  []byte
	Nonce       []byte
	State       string
	CommandID   uuid.UUID
	CreatedAt   time.Time
	ActivatedAt *time.Time
}

// UpsertPendingAdminPassword stores a password escrowed for a command. The
// agent may retry an escrow; the latest one for a command, still pending,
// replaces the earlier, since it is the one the agent is about to set.
func (q *Queries) UpsertPendingAdminPassword(ctx context.Context, p AdminPassword) error {
	_, err := q.db.Exec(ctx, `
		INSERT INTO local_admin_passwords (id, tenant_id, device_id, account, ciphertext, nonce, state, command_id, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, 'pending', $7, $8)
		ON CONFLICT (command_id) DO UPDATE
		SET account = EXCLUDED.account, ciphertext = EXCLUDED.ciphertext, nonce = EXCLUDED.nonce,
		    created_at = EXCLUDED.created_at
		WHERE local_admin_passwords.state = 'pending' AND local_admin_passwords.device_id = EXCLUDED.device_id`,
		p.ID, DefaultTenantID, p.DeviceID, p.Account, p.Ciphertext, p.Nonce, p.CommandID, p.CreatedAt)
	return err
}

// SettleAdminPassword finishes a command's pending password: active, which
// supersedes the account's previous active one, or abandoned.
func (q *Queries) SettleAdminPassword(ctx context.Context, commandID uuid.UUID, succeeded bool, at time.Time) error {
	if !succeeded {
		_, err := q.db.Exec(ctx, `
			UPDATE local_admin_passwords SET state = 'abandoned'
			WHERE tenant_id = $1 AND command_id = $2 AND state = 'pending'`, DefaultTenantID, commandID)
		return err
	}
	_, err := q.db.Exec(ctx, `
		WITH settled AS (
			UPDATE local_admin_passwords SET state = 'active', activated_at = $3
			WHERE tenant_id = $1 AND command_id = $2 AND state = 'pending'
			RETURNING id, device_id, account
		)
		UPDATE local_admin_passwords p SET state = 'superseded'
		FROM settled s
		WHERE p.tenant_id = $1 AND p.device_id = s.device_id AND lower(p.account) = lower(s.account)
		  AND p.state = 'active' AND p.id <> s.id`, DefaultTenantID, commandID, at)
	return err
}

// ListAdminPasswords returns a device's escrowed passwords, newest first,
// without the secrets.
func (q *Queries) ListAdminPasswords(ctx context.Context, deviceID uuid.UUID) ([]AdminPassword, error) {
	rows, err := q.db.Query(ctx, `
		SELECT p.id, p.device_id, d.hostname, p.account, p.state, p.command_id, p.created_at, p.activated_at
		FROM local_admin_passwords p JOIN devices d ON d.id = p.device_id
		WHERE p.tenant_id = $1 AND p.device_id = $2
		ORDER BY p.created_at DESC LIMIT 50`, DefaultTenantID, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AdminPassword
	for rows.Next() {
		var p AdminPassword
		if err := rows.Scan(&p.ID, &p.DeviceID, &p.Hostname, &p.Account, &p.State, &p.CommandID,
			&p.CreatedAt, &p.ActivatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// GetAdminPassword returns one escrowed password with its ciphertext.
func (q *Queries) GetAdminPassword(ctx context.Context, id uuid.UUID) (AdminPassword, error) {
	var p AdminPassword
	err := q.db.QueryRow(ctx, `
		SELECT p.id, p.device_id, d.hostname, p.account, p.ciphertext, p.nonce, p.state, p.command_id,
		       p.created_at, p.activated_at
		FROM local_admin_passwords p JOIN devices d ON d.id = p.device_id
		WHERE p.tenant_id = $1 AND p.id = $2`, DefaultTenantID, id).
		Scan(&p.ID, &p.DeviceID, &p.Hostname, &p.Account, &p.Ciphertext, &p.Nonce, &p.State, &p.CommandID,
			&p.CreatedAt, &p.ActivatedAt)
	return p, notFound(err)
}
