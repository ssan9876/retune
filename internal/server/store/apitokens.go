package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// APIToken is a credential for the admin API that is not a browser session.
// The token itself is never stored, only its hash.
type APIToken struct {
	ID          uuid.UUID
	Name        string
	TokenHash   []byte
	Role        string
	CreatedByID uuid.UUID
	CreatedBy   string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	LastUsedAt  *time.Time
	RevokedAt   *time.Time
}

const apiTokenCols = `id, name, token_hash, role, created_by_id, created_by, created_at, expires_at, last_used_at, revoked_at`

func scanAPIToken(row pgx.Row) (APIToken, error) {
	var t APIToken
	err := row.Scan(&t.ID, &t.Name, &t.TokenHash, &t.Role, &t.CreatedByID, &t.CreatedBy,
		&t.CreatedAt, &t.ExpiresAt, &t.LastUsedAt, &t.RevokedAt)
	return t, notFound(err)
}

func (q *Queries) CreateAPIToken(ctx context.Context, t APIToken) error {
	_, err := q.db.Exec(ctx, `
		INSERT INTO api_tokens (id, tenant_id, name, token_hash, role, created_by_id, created_by, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		t.ID, DefaultTenantID, t.Name, t.TokenHash, t.Role, t.CreatedByID, t.CreatedBy, t.CreatedAt, t.ExpiresAt)
	return duplicate(err)
}

// GetUsableAPIToken finds a token by its hash, but only if it is still one
// that should work: not revoked, not expired, and made by an admin who is
// not disabled. Anything else is ErrNotFound, so a caller cannot tell an
// unknown token from a dead one.
//
// The token's Role is capped at its maker's role now: an admin demoted to
// helpdesk holds only helpdesk tokens, whatever they were made as.
func (q *Queries) GetUsableAPIToken(ctx context.Context, hash []byte, now time.Time) (APIToken, error) {
	var t APIToken
	var creatorRole string
	err := q.db.QueryRow(ctx, `
		SELECT t.id, t.name, t.token_hash, t.role, t.created_by_id, t.created_by, t.created_at, t.expires_at,
		       t.last_used_at, t.revoked_at, a.role
		FROM api_tokens t JOIN admins a ON a.id = t.created_by_id AND a.tenant_id = t.tenant_id
		WHERE t.token_hash = $1 AND t.revoked_at IS NULL AND t.expires_at > $2 AND a.disabled_at IS NULL`,
		hash, now).Scan(&t.ID, &t.Name, &t.TokenHash, &t.Role, &t.CreatedByID, &t.CreatedBy,
		&t.CreatedAt, &t.ExpiresAt, &t.LastUsedAt, &t.RevokedAt, &creatorRole)
	if err != nil {
		return APIToken{}, notFound(err)
	}
	if RoleRank(creatorRole) < RoleRank(t.Role) {
		if !ValidRole(creatorRole) {
			return APIToken{}, ErrNotFound
		}
		t.Role = creatorRole
	}
	return t, nil
}

func (q *Queries) GetAPIToken(ctx context.Context, tenantID, id uuid.UUID) (APIToken, error) {
	return scanAPIToken(q.db.QueryRow(ctx,
		`SELECT `+apiTokenCols+` FROM api_tokens WHERE tenant_id = $1 AND id = $2`, tenantID, id))
}

// ListAPITokens returns every token, live ones first, newest first.
func (q *Queries) ListAPITokens(ctx context.Context) ([]APIToken, error) {
	rows, err := q.db.Query(ctx, `
		SELECT `+apiTokenCols+` FROM api_tokens WHERE tenant_id = $1
		ORDER BY revoked_at IS NOT NULL, created_at DESC, id DESC`, DefaultTenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []APIToken
	for rows.Next() {
		t, err := scanAPIToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// RevokeAPIToken reports whether a live token was revoked.
func (q *Queries) RevokeAPIToken(ctx context.Context, tenantID, id uuid.UUID, at time.Time) (bool, error) {
	tag, err := q.db.Exec(ctx,
		`UPDATE api_tokens SET revoked_at = $3 WHERE tenant_id = $1 AND id = $2 AND revoked_at IS NULL`,
		tenantID, id, at)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// RevokeAPITokensForAdmin revokes every live token an admin made and returns
// how many there were.
func (q *Queries) RevokeAPITokensForAdmin(ctx context.Context, tenantID, adminID uuid.UUID, at time.Time) (int64, error) {
	tag, err := q.db.Exec(ctx,
		`UPDATE api_tokens SET revoked_at = $3 WHERE tenant_id = $1 AND created_by_id = $2 AND revoked_at IS NULL`,
		tenantID, adminID, at)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// TouchAPIToken records a use.
func (q *Queries) TouchAPIToken(ctx context.Context, tenantID, id uuid.UUID, at time.Time) error {
	_, err := q.db.Exec(ctx,
		`UPDATE api_tokens SET last_used_at = $3 WHERE tenant_id = $1 AND id = $2`, tenantID, id, at)
	return err
}
