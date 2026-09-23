package store

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

// DeviceScope limits a query to the devices in some groups. Nil is no limit -
// the whole fleet - and an empty, non-nil scope matches no device at all: an
// admin scoped to groups that have all been deleted sees nothing, never
// everything.
type DeviceScope []uuid.UUID

// Unscoped is the scope of an admin who sees the whole fleet.
var Unscoped DeviceScope

// arg is the value bound for a scope placeholder: SQL NULL for no limit.
func (s DeviceScope) arg() any {
	if s == nil {
		return nil
	}
	return []uuid.UUID(s)
}

// Limited reports whether the scope limits anything.
func (s DeviceScope) Limited() bool { return s != nil }

// scopeSQL is the condition that limits deviceCol to the scope bound at
// placeholder n.
func scopeSQL(deviceCol string, n int) string {
	return fmt.Sprintf("($%d::uuid[] IS NULL OR %s IN (SELECT gm.device_id FROM group_members gm WHERE gm.group_id = ANY($%d::uuid[])))",
		n, deviceCol, n)
}

// DeviceInScope reports whether a device is one the scope reaches. An
// unscoped caller reaches every device.
func (q *Queries) DeviceInScope(ctx context.Context, tenantID, deviceID uuid.UUID, scope DeviceScope) (bool, error) {
	if !scope.Limited() {
		return true, nil
	}
	var ok bool
	err := q.db.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM group_members
		               WHERE tenant_id = $1 AND device_id = $2 AND group_id = ANY($3::uuid[]))`,
		tenantID, deviceID, scope.arg()).Scan(&ok)
	return ok, err
}

// AdminScope returns the groups an admin is limited to, or Unscoped. It is
// read on every request rather than carried in the session, so narrowing an
// admin takes effect at their next click.
func (q *Queries) AdminScope(ctx context.Context, tenantID, adminID uuid.UUID) (DeviceScope, error) {
	var scoped bool
	if err := q.db.QueryRow(ctx, `SELECT scoped FROM admins WHERE tenant_id = $1 AND id = $2`,
		tenantID, adminID).Scan(&scoped); err != nil {
		return nil, notFound(err)
	}
	if !scoped {
		return Unscoped, nil
	}
	rows, err := q.db.Query(ctx, `SELECT group_id FROM admin_scopes WHERE tenant_id = $1 AND admin_id = $2 ORDER BY group_id`,
		tenantID, adminID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := DeviceScope{}
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// SetAdminScope limits an admin to groups, or with Unscoped lifts the limit.
func (q *Queries) SetAdminScope(ctx context.Context, tenantID, adminID uuid.UUID, scope DeviceScope) error {
	if _, err := q.db.Exec(ctx, `DELETE FROM admin_scopes WHERE tenant_id = $1 AND admin_id = $2`, tenantID, adminID); err != nil {
		return err
	}
	if _, err := q.db.Exec(ctx, `UPDATE admins SET scoped = $3 WHERE tenant_id = $1 AND id = $2`,
		tenantID, adminID, scope.Limited()); err != nil {
		return err
	}
	for _, g := range scope {
		if _, err := q.db.Exec(ctx, `
			INSERT INTO admin_scopes (admin_id, group_id, tenant_id) VALUES ($1, $2, $3)
			ON CONFLICT DO NOTHING`, adminID, g, tenantID); err != nil {
			return err
		}
	}
	return nil
}
