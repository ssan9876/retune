package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Admin roles.
const (
	RoleAdmin    = "admin"
	RoleReadOnly = "read_only"
)

// Where an admin signs in: with a password here, or through the identity
// provider.
const (
	AuthLocal = "local"
	AuthOIDC  = "oidc"
)

// Admin is a console user.
type Admin struct {
	ID           uuid.UUID
	Email        string
	PasswordHash string
	TOTPSecret   string
	Role         string
	CreatedAt    time.Time
	LastLoginAt  *time.Time
	DisabledAt   *time.Time
	// AuthSource is AuthLocal or AuthOIDC. An OIDC account has no password
	// and no TOTP secret, and is identified by OIDCIssuer and OIDCSubject.
	AuthSource  string
	OIDCIssuer  string
	OIDCSubject string
	// Scoped says the admin is limited to some device groups (AdminScope
	// says which). Its own column rather than "has rows in admin_scopes", so
	// deleting the last of an admin's groups narrows them to nothing instead
	// of widening them to everything.
	Scoped bool
}

// Session is one signed-in browser. Only the hash of the token is stored.
type Session struct {
	TokenHash  []byte
	AdminID    uuid.UUID
	CSRFToken  string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	LastSeenAt time.Time
	UserAgent  string
	IP         string
}

const adminCols = `id, email, password_hash, totp_secret, role, created_at, last_login_at, disabled_at,
	auth_source, coalesce(oidc_issuer, ''), coalesce(oidc_subject, ''), scoped`

func scanAdmin(row pgx.Row) (Admin, error) {
	var a Admin
	err := row.Scan(&a.ID, &a.Email, &a.PasswordHash, &a.TOTPSecret, &a.Role, &a.CreatedAt, &a.LastLoginAt, &a.DisabledAt,
		&a.AuthSource, &a.OIDCIssuer, &a.OIDCSubject, &a.Scoped)
	return a, notFound(err)
}

func (q *Queries) CreateAdmin(ctx context.Context, a Admin) error {
	source := a.AuthSource
	if source == "" {
		source = AuthLocal
	}
	_, err := q.db.Exec(ctx, `
		INSERT INTO admins (id, tenant_id, email, password_hash, totp_secret, role, created_at,
		                    auth_source, oidc_issuer, oidc_subject)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULLIF($9, ''), NULLIF($10, ''))`,
		a.ID, DefaultTenantID, a.Email, a.PasswordHash, a.TOTPSecret, a.Role, a.CreatedAt,
		source, a.OIDCIssuer, a.OIDCSubject)
	return err
}

// GetAdminByOIDC finds the account an identity provider's subject signs in as.
func (q *Queries) GetAdminByOIDC(ctx context.Context, tenantID uuid.UUID, issuer, subject string) (Admin, error) {
	return scanAdmin(q.db.QueryRow(ctx,
		`SELECT `+adminCols+` FROM admins WHERE tenant_id = $1 AND oidc_issuer = $2 AND oidc_subject = $3`,
		tenantID, issuer, subject))
}

// UpdateOIDCAdmin refreshes what the provider says about an account at each
// sign-in: its email, which the provider owns, and its role, which is worked
// out again from the groups claim every time.
func (q *Queries) UpdateOIDCAdmin(ctx context.Context, tenantID, id uuid.UUID, email, role string) error {
	_, err := q.db.Exec(ctx,
		`UPDATE admins SET email = $3, role = $4 WHERE tenant_id = $1 AND id = $2 AND auth_source = 'oidc'`,
		tenantID, id, email, role)
	return err
}

func (q *Queries) GetAdmin(ctx context.Context, tenantID, id uuid.UUID) (Admin, error) {
	return scanAdmin(q.db.QueryRow(ctx,
		`SELECT `+adminCols+` FROM admins WHERE tenant_id = $1 AND id = $2`, tenantID, id))
}

// GetAdminByEmail looks an admin up case-insensitively.
func (q *Queries) GetAdminByEmail(ctx context.Context, tenantID uuid.UUID, email string) (Admin, error) {
	return scanAdmin(q.db.QueryRow(ctx,
		`SELECT `+adminCols+` FROM admins WHERE tenant_id = $1 AND lower(email) = lower($2)`, tenantID, email))
}

func (q *Queries) ListAdmins(ctx context.Context) ([]Admin, error) {
	rows, err := q.db.Query(ctx, `SELECT `+adminCols+` FROM admins WHERE tenant_id = $1 ORDER BY created_at, id`, DefaultTenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Admin
	for rows.Next() {
		a, err := scanAdmin(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (q *Queries) CountAdmins(ctx context.Context) (int, error) {
	var n int
	err := q.db.QueryRow(ctx, `SELECT count(*) FROM admins WHERE tenant_id = $1`, DefaultTenantID).Scan(&n)
	return n, err
}

func (q *Queries) UpdateAdminPassword(ctx context.Context, tenantID, id uuid.UUID, hash string) error {
	_, err := q.db.Exec(ctx,
		`UPDATE admins SET password_hash = $3 WHERE tenant_id = $1 AND id = $2`, tenantID, id, hash)
	return err
}

// UpdateAdminTOTP stores a new TOTP secret, or "" to turn TOTP off.
func (q *Queries) UpdateAdminTOTP(ctx context.Context, tenantID, id uuid.UUID, secret string) error {
	_, err := q.db.Exec(ctx,
		`UPDATE admins SET totp_secret = $3 WHERE tenant_id = $1 AND id = $2`, tenantID, id, secret)
	return err
}

// SetAdminDisabled disables an admin, or re-enables it with a nil time.
func (q *Queries) SetAdminDisabled(ctx context.Context, tenantID, id uuid.UUID, at *time.Time) error {
	_, err := q.db.Exec(ctx,
		`UPDATE admins SET disabled_at = $3 WHERE tenant_id = $1 AND id = $2`, tenantID, id, at)
	return err
}

func (q *Queries) RecordAdminLogin(ctx context.Context, tenantID, id uuid.UUID, at time.Time) error {
	_, err := q.db.Exec(ctx,
		`UPDATE admins SET last_login_at = $3 WHERE tenant_id = $1 AND id = $2`, tenantID, id, at)
	return err
}

func (q *Queries) CreateSession(ctx context.Context, s Session) error {
	_, err := q.db.Exec(ctx, `
		INSERT INTO sessions (token_hash, tenant_id, admin_id, csrf_token, created_at, expires_at, last_seen_at, user_agent, ip)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		s.TokenHash, DefaultTenantID, s.AdminID, s.CSRFToken, s.CreatedAt, s.ExpiresAt, s.LastSeenAt, s.UserAgent, s.IP)
	return err
}

// GetSessionWithAdmin returns a session and its owner in one round trip.
func (q *Queries) GetSessionWithAdmin(ctx context.Context, tokenHash []byte) (Session, Admin, error) {
	var s Session
	var a Admin
	err := q.db.QueryRow(ctx, `
		SELECT s.token_hash, s.admin_id, s.csrf_token, s.created_at, s.expires_at, s.last_seen_at, s.user_agent, s.ip,
		       a.id, a.email, a.password_hash, a.totp_secret, a.role, a.created_at, a.last_login_at, a.disabled_at,
		       a.auth_source, coalesce(a.oidc_issuer, ''), coalesce(a.oidc_subject, ''), a.scoped
		FROM sessions s JOIN admins a ON a.id = s.admin_id
		WHERE s.token_hash = $1`, tokenHash).
		Scan(&s.TokenHash, &s.AdminID, &s.CSRFToken, &s.CreatedAt, &s.ExpiresAt, &s.LastSeenAt, &s.UserAgent, &s.IP,
			&a.ID, &a.Email, &a.PasswordHash, &a.TOTPSecret, &a.Role, &a.CreatedAt, &a.LastLoginAt, &a.DisabledAt,
			&a.AuthSource, &a.OIDCIssuer, &a.OIDCSubject, &a.Scoped)
	if err != nil {
		return Session{}, Admin{}, notFound(err)
	}
	return s, a, nil
}

func (q *Queries) TouchSession(ctx context.Context, tokenHash []byte, seenAt, expiresAt time.Time) error {
	_, err := q.db.Exec(ctx, `
		UPDATE sessions SET last_seen_at = $2, expires_at = $3 WHERE token_hash = $1`, tokenHash, seenAt, expiresAt)
	return err
}

func (q *Queries) DeleteSession(ctx context.Context, tokenHash []byte) error {
	_, err := q.db.Exec(ctx, `DELETE FROM sessions WHERE token_hash = $1`, tokenHash)
	return err
}

func (q *Queries) DeleteSessionsForAdmin(ctx context.Context, adminID uuid.UUID) error {
	_, err := q.db.Exec(ctx, `DELETE FROM sessions WHERE tenant_id = $1 AND admin_id = $2`, DefaultTenantID, adminID)
	return err
}

func (q *Queries) DeleteExpiredSessions(ctx context.Context, now time.Time) (int64, error) {
	tag, err := q.db.Exec(ctx, `DELETE FROM sessions WHERE expires_at <= $1`, now)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
