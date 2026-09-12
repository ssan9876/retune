package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const tokenCols = `id, token_hash, label, expires_at, max_uses, use_count, revoked_at, created_by, created_at`

func scanToken(row pgx.Row) (EnrollmentToken, error) {
	var t EnrollmentToken
	err := row.Scan(&t.ID, &t.TokenHash, &t.Label, &t.ExpiresAt, &t.MaxUses, &t.UseCount, &t.RevokedAt, &t.CreatedBy, &t.CreatedAt)
	return t, notFound(err)
}

func (q *Queries) CreateEnrollmentToken(ctx context.Context, t EnrollmentToken) error {
	if t.CreatedAt.IsZero() {
		t.CreatedAt = time.Now().UTC()
	}
	_, err := q.db.Exec(ctx, `
		INSERT INTO enrollment_tokens (id, tenant_id, token_hash, label, expires_at, max_uses, created_by, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		t.ID, DefaultTenantID, t.TokenHash, t.Label, t.ExpiresAt, t.MaxUses, t.CreatedBy, t.CreatedAt)
	return err
}

func (q *Queries) GetEnrollmentToken(ctx context.Context, id uuid.UUID) (EnrollmentToken, error) {
	return scanToken(q.db.QueryRow(ctx, `SELECT `+tokenCols+` FROM enrollment_tokens WHERE id = $1`, id))
}

// GetEnrollmentTokenByHashForUpdate locks the token row; call inside InTx.
func (q *Queries) GetEnrollmentTokenByHashForUpdate(ctx context.Context, hash []byte) (EnrollmentToken, error) {
	return scanToken(q.db.QueryRow(ctx, `SELECT `+tokenCols+` FROM enrollment_tokens WHERE token_hash = $1 FOR UPDATE`, hash))
}

func (q *Queries) IncrementTokenUse(ctx context.Context, id uuid.UUID) error {
	_, err := q.db.Exec(ctx, `UPDATE enrollment_tokens SET use_count = use_count + 1 WHERE id = $1`, id)
	return err
}

func (q *Queries) RevokeEnrollmentToken(ctx context.Context, id uuid.UUID, at time.Time) error {
	_, err := q.db.Exec(ctx, `UPDATE enrollment_tokens SET revoked_at = $2 WHERE id = $1 AND revoked_at IS NULL`, id, at)
	return err
}
