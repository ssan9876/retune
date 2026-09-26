package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ServerRunningLock is held, shared, by every running server for as long as
// it runs. Rotating the secret key takes it exclusively, so it can't start
// while a server is up - one that would go on sealing new secrets under the
// old key, or fail to open the re-sealed ones.
const ServerRunningLock = 5274010

// ErrServerRunning is the exclusive lock refused: a server is running.
var ErrServerRunning = errors.New("a Retune server is running against this database")

// HoldRunningLock takes ServerRunningLock, shared, and keeps it until
// release is called. It holds it on a connection of its own, outside the
// pool, so closing the pool never waits for it; if that connection drops,
// Postgres releases the lock with it.
func (s *Store) HoldRunningLock(ctx context.Context) (release func(), err error) {
	conn, err := pgx.ConnectConfig(ctx, s.pool.Config().ConnConfig.Copy())
	if err != nil {
		return nil, err
	}
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock_shared($1)`, ServerRunningLock); err != nil {
		_ = conn.Close(ctx)
		return nil, err
	}
	return func() {
		closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		// Unlock explicitly before closing: closing the session releases the
		// lock too, but only once the backend has exited, which is after Close
		// returns, so a rekey started straight after would still see it held.
		_, _ = conn.Exec(closeCtx, `SELECT pg_advisory_unlock_shared($1)`, ServerRunningLock)
		_ = conn.Close(closeCtx)
	}, nil
}

// WithServersStopped runs fn in a transaction while holding ServerRunningLock
// exclusively, or returns ErrServerRunning without running it.
func (s *Store) WithServersStopped(ctx context.Context, fn func(q *Queries) error) error {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	var got bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, ServerRunningLock).Scan(&got); err != nil {
		conn.Release()
		return err
	}
	if !got {
		conn.Release()
		return ErrServerRunning
	}
	defer unlock(ctx, conn, `SELECT pg_advisory_unlock($1)`)
	return pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error { return fn(&Queries{db: tx}) })
}

func unlock(ctx context.Context, conn *pgxpool.Conn, sql string) {
	defer conn.Release()
	unlockCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_, _ = conn.Exec(unlockCtx, sql, ServerRunningLock)
}

// SealedValue is one ciphertext stored in a bytea pair of columns, with what
// its context is built from.
type SealedValue struct {
	ID         uuid.UUID
	DeviceID   uuid.UUID
	Name       string // volume id, account; empty for a channel
	Ciphertext []byte
	Nonce      []byte
}

func (q *Queries) sealedValues(ctx context.Context, sql string) ([]SealedValue, error) {
	rows, err := q.db.Query(ctx, sql, DefaultTenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SealedValue
	for rows.Next() {
		var v SealedValue
		if err := rows.Scan(&v.ID, &v.DeviceID, &v.Name, &v.Ciphertext, &v.Nonce); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// SealedBitLockerKeys returns every escrowed recovery key, sealed.
func (q *Queries) SealedBitLockerKeys(ctx context.Context) ([]SealedValue, error) {
	return q.sealedValues(ctx, `SELECT id, device_id, volume_id, ciphertext, nonce FROM bitlocker_keys WHERE tenant_id = $1 FOR UPDATE`)
}

// SealedAdminPasswords returns every escrowed local admin password, sealed.
func (q *Queries) SealedAdminPasswords(ctx context.Context) ([]SealedValue, error) {
	return q.sealedValues(ctx, `SELECT id, device_id, account, ciphertext, nonce FROM local_admin_passwords WHERE tenant_id = $1 FOR UPDATE`)
}

// SealedChannelSecrets returns every notification channel's secret, sealed.
func (q *Queries) SealedChannelSecrets(ctx context.Context) ([]SealedValue, error) {
	return q.sealedValues(ctx, `
		SELECT id, '00000000-0000-0000-0000-000000000000'::uuid, '', secret_ciphertext, secret_nonce
		FROM notification_channels WHERE tenant_id = $1 AND secret_ciphertext IS NOT NULL FOR UPDATE`)
}

// SetBitLockerKeySealed, SetAdminPasswordSealed and SetChannelSecretSealed
// replace one sealed value.
func (q *Queries) SetBitLockerKeySealed(ctx context.Context, id uuid.UUID, ciphertext, nonce []byte) error {
	return q.setSealed(ctx, `UPDATE bitlocker_keys SET ciphertext = $3, nonce = $4 WHERE tenant_id = $1 AND id = $2`, id, ciphertext, nonce)
}

func (q *Queries) SetAdminPasswordSealed(ctx context.Context, id uuid.UUID, ciphertext, nonce []byte) error {
	return q.setSealed(ctx, `UPDATE local_admin_passwords SET ciphertext = $3, nonce = $4 WHERE tenant_id = $1 AND id = $2`, id, ciphertext, nonce)
}

func (q *Queries) SetChannelSecretSealed(ctx context.Context, id uuid.UUID, ciphertext, nonce []byte) error {
	return q.setSealed(ctx, `UPDATE notification_channels SET secret_ciphertext = $3, secret_nonce = $4 WHERE tenant_id = $1 AND id = $2`, id, ciphertext, nonce)
}

func (q *Queries) setSealed(ctx context.Context, sql string, id uuid.UUID, ciphertext, nonce []byte) error {
	tag, err := q.db.Exec(ctx, sql, DefaultTenantID, id, ciphertext, nonce)
	if err == nil && tag.RowsAffected() != 1 {
		return ErrNotFound
	}
	return err
}

// SealedTOTP is an admin's sealed authenticator secret.
type SealedTOTP struct {
	AdminID uuid.UUID
	Stored  string
}

// SealedTOTPSecrets returns every admin's authenticator secret that is set.
func (q *Queries) SealedTOTPSecrets(ctx context.Context) ([]SealedTOTP, error) {
	rows, err := q.db.Query(ctx, `SELECT id, totp_secret FROM admins WHERE tenant_id = $1 AND totp_secret <> '' FOR UPDATE`, DefaultTenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SealedTOTP
	for rows.Next() {
		var t SealedTOTP
		if err := rows.Scan(&t.AdminID, &t.Stored); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// SetTOTPSealed replaces an admin's stored authenticator secret.
func (q *Queries) SetTOTPSealed(ctx context.Context, adminID uuid.UUID, stored string) error {
	_, err := q.db.Exec(ctx, `UPDATE admins SET totp_secret = $3 WHERE tenant_id = $1 AND id = $2`, DefaultTenantID, adminID, stored)
	return err
}

// StoredProfileVersion is one profile version's stored settings.
type StoredProfileVersion struct {
	ProfileID uuid.UUID
	Version   int
	Settings  []byte
}

// ProfileVersionsWithSecrets returns every profile version whose settings
// hold a sealed secret.
func (q *Queries) ProfileVersionsWithSecrets(ctx context.Context) ([]StoredProfileVersion, error) {
	rows, err := q.db.Query(ctx, `
		SELECT v.profile_id, v.version, v.settings FROM profile_versions v
		JOIN profiles p ON p.id = v.profile_id AND p.tenant_id = $1
		WHERE v.settings::text LIKE '%sealed_secret%'
		FOR UPDATE OF v`, DefaultTenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []StoredProfileVersion
	for rows.Next() {
		var v StoredProfileVersion
		if err := rows.Scan(&v.ProfileID, &v.Version, &v.Settings); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// SetProfileVersionSettings replaces one version's stored settings and hash.
func (q *Queries) SetProfileVersionSettings(ctx context.Context, profileID uuid.UUID, version int, settings []byte, hash string) error {
	_, err := q.db.Exec(ctx, `UPDATE profile_versions SET settings = $3, hash = $4 WHERE profile_id = $1 AND version = $2`,
		profileID, version, settings, hash)
	return err
}
