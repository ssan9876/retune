package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Group kinds.
const (
	GroupStatic  = "static"
	GroupDynamic = "dynamic"
	GroupBuiltin = "builtin"
)

// Assignment modes.
const (
	ModeInclude = "include"
	ModeExclude = "exclude"
)

// BuiltinGroupID is the seeded "All devices" group.
var BuiltinGroupID = uuid.MustParse("00000000-0000-0000-0000-000000000002")

// Group is a set of devices, either listed explicitly or matched by a rule.
type Group struct {
	ID          uuid.UUID
	Name        string
	Description string
	Kind        string
	Rule        string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	EvaluatedAt *time.Time
}

// Assignment attaches an item to a group. The item is opaque here: the tables
// it refers to arrive with scripts and profiles.
type Assignment struct {
	ID        uuid.UUID
	ItemKind  string
	ItemID    uuid.UUID
	GroupID   uuid.UUID
	Mode      string
	CreatedAt time.Time
	CreatedBy string
	// Options configure the deployment; their shape depends on the kind.
	Options []byte
}

// Item identifies one assigned thing, with the options of the assignment that
// won.
type Item struct {
	Kind    string
	ID      uuid.UUID
	Options []byte
}

const groupCols = `id, name, description, kind, rule, created_at, updated_at, evaluated_at`

func scanGroup(row pgx.Row) (Group, error) {
	var g Group
	err := row.Scan(&g.ID, &g.Name, &g.Description, &g.Kind, &g.Rule, &g.CreatedAt, &g.UpdatedAt, &g.EvaluatedAt)
	return g, notFound(err)
}

func (q *Queries) CreateGroup(ctx context.Context, g Group) error {
	_, err := q.db.Exec(ctx, `
		INSERT INTO device_groups (id, tenant_id, name, description, kind, rule, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $7)`,
		g.ID, DefaultTenantID, g.Name, g.Description, g.Kind, g.Rule, g.CreatedAt)
	return err
}

func (q *Queries) GetGroup(ctx context.Context, id uuid.UUID) (Group, error) {
	return scanGroup(q.db.QueryRow(ctx, `SELECT `+groupCols+` FROM device_groups WHERE id = $1`, id))
}

// GetGroupByName finds a group by its case-insensitive name.
func (q *Queries) GetGroupByName(ctx context.Context, name string) (Group, error) {
	return scanGroup(q.db.QueryRow(ctx,
		`SELECT `+groupCols+` FROM device_groups WHERE tenant_id = $1 AND lower(name) = lower($2)`,
		DefaultTenantID, name))
}

// GroupWithCount is a group plus how many devices are in it.
type GroupWithCount struct {
	Group
	MemberCount int
}

// ListGroups returns every group with its membership count, built-in first.
func (q *Queries) ListGroups(ctx context.Context) ([]GroupWithCount, error) {
	rows, err := q.db.Query(ctx, `
		SELECT g.id, g.name, g.description, g.kind, g.rule, g.created_at, g.updated_at, g.evaluated_at,
		       (SELECT count(*) FROM group_members m WHERE m.group_id = g.id) AS members
		FROM device_groups g
		WHERE g.tenant_id = $1
		ORDER BY (g.kind = 'builtin') DESC, lower(g.name)`, DefaultTenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GroupWithCount
	for rows.Next() {
		var g GroupWithCount
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.Kind, &g.Rule,
			&g.CreatedAt, &g.UpdatedAt, &g.EvaluatedAt, &g.MemberCount); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func (q *Queries) UpdateGroup(ctx context.Context, g Group) error {
	_, err := q.db.Exec(ctx, `
		UPDATE device_groups SET name = $2, description = $3, rule = $4, updated_at = $5
		WHERE id = $1`, g.ID, g.Name, g.Description, g.Rule, g.UpdatedAt)
	return err
}

// DeleteGroup removes a group; its membership and assignments cascade.
func (q *Queries) DeleteGroup(ctx context.Context, id uuid.UUID) error {
	_, err := q.db.Exec(ctx, `DELETE FROM device_groups WHERE id = $1`, id)
	return err
}

// DynamicGroups returns the groups whose membership is derived, which is every
// dynamic group plus the built-in one.
func (q *Queries) DynamicGroups(ctx context.Context) ([]Group, error) {
	rows, err := q.db.Query(ctx, `
		SELECT `+groupCols+` FROM device_groups
		WHERE tenant_id = $1 AND kind IN ('dynamic', 'builtin')
		ORDER BY lower(name)`, DefaultTenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Group
	for rows.Next() {
		var g Group
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.Kind, &g.Rule,
			&g.CreatedAt, &g.UpdatedAt, &g.EvaluatedAt); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// SetGroupMembers replaces a derived group's membership wholesale. Callers run
// it inside a transaction so a group is never observed half-evaluated.
func (q *Queries) SetGroupMembers(ctx context.Context, groupID uuid.UUID, deviceIDs []uuid.UUID, now time.Time) error {
	if _, err := q.db.Exec(ctx,
		`DELETE FROM group_members WHERE group_id = $1 AND NOT (device_id = ANY($2::uuid[]))`,
		groupID, deviceIDs); err != nil {
		return err
	}
	if len(deviceIDs) == 0 {
		return q.markGroupEvaluated(ctx, groupID, now)
	}
	if _, err := q.db.Exec(ctx, `
		INSERT INTO group_members (group_id, device_id, tenant_id, added_at)
		SELECT $1, d, $3, $4 FROM unnest($2::uuid[]) AS d
		ON CONFLICT (group_id, device_id) DO NOTHING`,
		groupID, deviceIDs, DefaultTenantID, now); err != nil {
		return err
	}
	return q.markGroupEvaluated(ctx, groupID, now)
}

func (q *Queries) markGroupEvaluated(ctx context.Context, groupID uuid.UUID, now time.Time) error {
	_, err := q.db.Exec(ctx, `UPDATE device_groups SET evaluated_at = $2 WHERE id = $1`, groupID, now)
	return err
}

// SetDeviceGroupMembership adds or removes one device from one derived group,
// used when a single device's inventory changes.
func (q *Queries) SetDeviceGroupMembership(ctx context.Context, groupID, deviceID uuid.UUID, member bool, now time.Time) error {
	if !member {
		_, err := q.db.Exec(ctx, `DELETE FROM group_members WHERE group_id = $1 AND device_id = $2`, groupID, deviceID)
		return err
	}
	_, err := q.db.Exec(ctx, `
		INSERT INTO group_members (group_id, device_id, tenant_id, added_at)
		VALUES ($1, $2, $3, $4) ON CONFLICT (group_id, device_id) DO NOTHING`,
		groupID, deviceID, DefaultTenantID, now)
	return err
}

func (q *Queries) AddGroupMember(ctx context.Context, groupID, deviceID uuid.UUID, now time.Time) error {
	return q.SetDeviceGroupMembership(ctx, groupID, deviceID, true, now)
}

func (q *Queries) RemoveGroupMember(ctx context.Context, groupID, deviceID uuid.UUID) error {
	return q.SetDeviceGroupMembership(ctx, groupID, deviceID, false, time.Time{})
}

// ListGroupMembers returns one page of a group's devices.
func (q *Queries) ListGroupMembers(ctx context.Context, groupID uuid.UUID, page Page) ([]Device, int, error) {
	p := page.Normalized()
	rows, err := q.db.Query(ctx, `
		SELECT d.id, d.hostname, d.serial, d.smbios_uuid, d.os_version, d.status, d.cert_serial,
		       d.cert_expires_at, d.last_seen_at, d.agent_version, d.enrolled_at, d.replaced_by,
		       d.prev_cert_serial, d.os_build, d.manufacturer, d.model, count(*) OVER () AS total
		FROM group_members m
		JOIN devices d ON d.id = m.device_id
		WHERE m.group_id = $1
		ORDER BY lower(d.hostname), d.enrolled_at
		LIMIT $2 OFFSET $3`, groupID, p.Limit, p.Offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []Device
	total := 0
	for rows.Next() {
		var d Device
		if err := rows.Scan(&d.ID, &d.Hostname, &d.Serial, &d.SMBIOSUUID, &d.OSVersion, &d.Status, &d.CertSerial,
			&d.CertExpiresAt, &d.LastSeenAt, &d.AgentVersion, &d.EnrolledAt, &d.ReplacedBy,
			&d.PrevCertSerial, &d.OSBuild, &d.Manufacturer, &d.Model, &total); err != nil {
			return nil, 0, err
		}
		out = append(out, d)
	}
	return out, total, rows.Err()
}

// ListGroupsForDevice returns the groups one device belongs to.
func (q *Queries) ListGroupsForDevice(ctx context.Context, deviceID uuid.UUID) ([]Group, error) {
	rows, err := q.db.Query(ctx, `
		SELECT g.id, g.name, g.description, g.kind, g.rule, g.created_at, g.updated_at, g.evaluated_at
		FROM group_members m
		JOIN device_groups g ON g.id = m.group_id
		WHERE m.device_id = $1
		ORDER BY lower(g.name)`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Group
	for rows.Next() {
		var g Group
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.Kind, &g.Rule,
			&g.CreatedAt, &g.UpdatedAt, &g.EvaluatedAt); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// MatchDevices runs a compiled rule and returns the matching device IDs.
func (q *Queries) MatchDevices(ctx context.Context, sql string, args []any) ([]uuid.UUID, error) {
	rows, err := q.db.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// DevicesByIDs returns one page of the named devices, used to show what a rule
// preview matched.
func (q *Queries) DevicesByIDs(ctx context.Context, ids []uuid.UUID, page Page) ([]Device, error) {
	p := page.Normalized()
	rows, err := q.db.Query(ctx, `
		SELECT `+deviceCols+` FROM devices
		WHERE id = ANY($1::uuid[])
		ORDER BY lower(hostname), enrolled_at
		LIMIT $2 OFFSET $3`, ids, p.Limit, p.Offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Device
	for rows.Next() {
		var d Device
		if err := rows.Scan(&d.ID, &d.Hostname, &d.Serial, &d.SMBIOSUUID, &d.OSVersion, &d.Status, &d.CertSerial,
			&d.CertExpiresAt, &d.LastSeenAt, &d.AgentVersion, &d.EnrolledAt, &d.ReplacedBy,
			&d.PrevCertSerial, &d.OSBuild, &d.Manufacturer, &d.Model); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// ActiveDeviceIDs returns every active device, which is the built-in group's
// membership.
func (q *Queries) ActiveDeviceIDs(ctx context.Context) ([]uuid.UUID, error) {
	return q.MatchDevices(ctx,
		`SELECT id FROM devices WHERE tenant_id = $1 AND status = 'active'`,
		[]any{DefaultTenantID})
}

// CreateAssignment stores an assignment for (item, group, mode). The unique
// index on those columns means a second call for the same triple is not an
// error: it is how an administrator changes the item's options after the
// fact, including flipping an app's assignment from install to uninstall,
// and there is no other way to do that short of deleting and recreating the
// assignment (which would drop it — and any pending agent instruction with
// it — for the time in between). So a conflict replaces the row's options,
// created_at and created_by rather than failing. The row keeps its original
// id across a replacement, which is why the id is returned rather than
// assumed to be a.ID: a caller that echoed the generated id back after a
// conflict would be naming a row that was never written.
func (q *Queries) CreateAssignment(ctx context.Context, a Assignment) (uuid.UUID, error) {
	var id uuid.UUID
	err := q.db.QueryRow(ctx, `
		INSERT INTO assignments (id, tenant_id, item_kind, item_id, group_id, mode, created_at, created_by, options)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, coalesce($9, '{}'::jsonb))
		ON CONFLICT (item_kind, item_id, group_id, mode)
		DO UPDATE SET options = EXCLUDED.options, created_at = EXCLUDED.created_at, created_by = EXCLUDED.created_by
		RETURNING id`,
		a.ID, DefaultTenantID, a.ItemKind, a.ItemID, a.GroupID, a.Mode, a.CreatedAt, a.CreatedBy, a.Options).
		Scan(&id)
	return id, err
}

// DeleteAssignmentsForItem removes every assignment of one item, used when the
// item itself is deleted.
func (q *Queries) DeleteAssignmentsForItem(ctx context.Context, kind string, itemID uuid.UUID) error {
	_, err := q.db.Exec(ctx,
		`DELETE FROM assignments WHERE tenant_id = $1 AND item_kind = $2 AND item_id = $3`,
		DefaultTenantID, kind, itemID)
	return err
}

func (q *Queries) DeleteAssignment(ctx context.Context, id uuid.UUID) error {
	_, err := q.db.Exec(ctx, `DELETE FROM assignments WHERE id = $1`, id)
	return err
}

func (q *Queries) GetAssignment(ctx context.Context, id uuid.UUID) (Assignment, error) {
	var a Assignment
	err := q.db.QueryRow(ctx, `
		SELECT id, item_kind, item_id, group_id, mode, created_at, created_by, options
		FROM assignments WHERE id = $1`, id).
		Scan(&a.ID, &a.ItemKind, &a.ItemID, &a.GroupID, &a.Mode, &a.CreatedAt, &a.CreatedBy, &a.Options)
	return a, notFound(err)
}

// ListAssignments returns the assignments for one item.
func (q *Queries) ListAssignments(ctx context.Context, itemKind string, itemID uuid.UUID) ([]Assignment, error) {
	rows, err := q.db.Query(ctx, `
		SELECT id, item_kind, item_id, group_id, mode, created_at, created_by, options
		FROM assignments
		WHERE tenant_id = $1 AND item_kind = $2 AND item_id = $3
		ORDER BY mode, created_at`, DefaultTenantID, itemKind, itemID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Assignment
	for rows.Next() {
		var a Assignment
		if err := rows.Scan(&a.ID, &a.ItemKind, &a.ItemID, &a.GroupID, &a.Mode,
			&a.CreatedAt, &a.CreatedBy, &a.Options); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// EffectiveItems returns the items assigned to a device: everything included
// through one of its groups and excluded through none of them. Exclude always
// wins, whichever group it came from.
func (q *Queries) EffectiveItems(ctx context.Context, deviceID uuid.UUID) ([]Item, error) {
	// DISTINCT ON with the ordering below is the conflict rule: when the same
	// item reaches a device through several groups, the most recently created
	// include assignment supplies the options.
	rows, err := q.db.Query(ctx, `
		SELECT DISTINCT ON (a.item_kind, a.item_id) a.item_kind, a.item_id, a.options
		FROM assignments a
		JOIN group_members gm ON gm.group_id = a.group_id AND gm.device_id = $1
		WHERE a.mode = 'include'
		  AND NOT EXISTS (
		      SELECT 1 FROM assignments x
		      JOIN group_members gx ON gx.group_id = x.group_id AND gx.device_id = $1
		      WHERE x.mode = 'exclude'
		        AND x.item_kind = a.item_kind AND x.item_id = a.item_id)
		ORDER BY a.item_kind, a.item_id, a.created_at DESC`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Item
	for rows.Next() {
		var it Item
		if err := rows.Scan(&it.Kind, &it.ID, &it.Options); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}
