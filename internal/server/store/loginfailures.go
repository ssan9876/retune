package store

import (
	"context"
	"time"
)

// CountLoginFailures is how many failed sign-ins key has had since since.
func (q *Queries) CountLoginFailures(ctx context.Context, key string, since time.Time) (int, error) {
	var n int
	err := q.db.QueryRow(ctx,
		`SELECT count(*) FROM login_failures WHERE tenant_id = $1 AND key = $2 AND at > $3`,
		DefaultTenantID, key, since).Scan(&n)
	return n, err
}

// RecordLoginFailure notes a failed sign-in, and forgets every failure older
// than expired, so the table only ever holds the current window.
func (q *Queries) RecordLoginFailure(ctx context.Context, key string, at, expired time.Time) error {
	if _, err := q.db.Exec(ctx, `DELETE FROM login_failures WHERE at <= $1`, expired); err != nil {
		return err
	}
	_, err := q.db.Exec(ctx, `INSERT INTO login_failures (tenant_id, key, at) VALUES ($1, $2, $3)`, DefaultTenantID, key, at)
	return err
}

// ClearLoginFailures forgets a key's failures after it signs in.
func (q *Queries) ClearLoginFailures(ctx context.Context, key string) error {
	_, err := q.db.Exec(ctx, `DELETE FROM login_failures WHERE tenant_id = $1 AND key = $2`, DefaultTenantID, key)
	return err
}
