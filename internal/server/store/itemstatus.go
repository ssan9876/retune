package store

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Item statuses, as reported per device.
const (
	ItemPending       = "pending"
	ItemSucceeded     = "succeeded"
	ItemFailed        = "failed"
	ItemConflict      = "conflict"
	ItemNotApplicable = "not_applicable"
)

// ItemStatus is how one item is faring on one device.
type ItemStatus struct {
	DeviceID uuid.UUID
	// Hostname is filled in by the listing queries, not by SetItemStatus.
	Hostname string
	ItemKind string
	ItemID   uuid.UUID
	Status   string
	Detail   string
	// Version is the item version this status refers to, so the console can
	// say "succeeded on version 3" rather than just "succeeded".
	Version   int
	UpdatedAt time.Time
}

// SetItemStatus records the latest state of an item on a device.
func (q *Queries) SetItemStatus(ctx context.Context, s ItemStatus) error {
	_, err := q.db.Exec(ctx, `
		INSERT INTO device_item_status (device_id, tenant_id, item_kind, item_id, status, detail, version, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (device_id, item_kind, item_id) DO UPDATE
		SET status = EXCLUDED.status, detail = EXCLUDED.detail,
		    version = EXCLUDED.version, updated_at = EXCLUDED.updated_at`,
		s.DeviceID, DefaultTenantID, s.ItemKind, s.ItemID, s.Status, s.Detail, s.Version, s.UpdatedAt)
	return err
}

// MarkItemSucceededOnce records success for an item on a device, unless it is
// already recorded: it is called on every check-in for every assigned agent
// build the device is running, and rewriting the row each time would make
// updated_at mean "last check-in" rather than "when this was learned".
func (q *Queries) MarkItemSucceededOnce(ctx context.Context, s ItemStatus) error {
	_, err := q.db.Exec(ctx, `
		INSERT INTO device_item_status (device_id, tenant_id, item_kind, item_id, status, detail, version, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (device_id, item_kind, item_id) DO UPDATE
		SET status = EXCLUDED.status, detail = EXCLUDED.detail,
		    version = EXCLUDED.version, updated_at = EXCLUDED.updated_at
		WHERE device_item_status.status <> EXCLUDED.status`,
		s.DeviceID, DefaultTenantID, s.ItemKind, s.ItemID, ItemSucceeded, s.Detail, s.Version, s.UpdatedAt)
	return err
}

// ItemStatusRollup counts devices by status for one item, for the console's
// per-item summary.
func (q *Queries) ItemStatusRollup(ctx context.Context, itemKind string, itemID uuid.UUID) (map[string]int, error) {
	rows, err := q.db.Query(ctx, `
		SELECT status, count(*) FROM device_item_status
		WHERE tenant_id = $1 AND item_kind = $2 AND item_id = $3
		GROUP BY status`, DefaultTenantID, itemKind, itemID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var status string
		var n int
		if err := rows.Scan(&status, &n); err != nil {
			return nil, err
		}
		out[status] = n
	}
	return out, rows.Err()
}

// ListItemStatus returns one page of devices for an item, optionally narrowed
// to a single status, for drilling into a rollup.
func (q *Queries) ListItemStatus(ctx context.Context, itemKind string, itemID uuid.UUID, status string, page Page) ([]ItemStatus, int, error) {
	p := page.Normalized()
	rows, err := q.db.Query(ctx, `
		SELECT s.device_id, d.hostname, s.item_kind, s.item_id, s.status, s.detail, s.version, s.updated_at,
		       count(*) OVER () AS total
		FROM device_item_status s
		JOIN devices d ON d.id = s.device_id
		WHERE s.tenant_id = $1 AND s.item_kind = $2 AND s.item_id = $3
		  AND ($4 = '' OR s.status = $4)
		ORDER BY lower(d.hostname)
		LIMIT $5 OFFSET $6`, DefaultTenantID, itemKind, itemID, status, p.Limit, p.Offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []ItemStatus
	total := 0
	for rows.Next() {
		var s ItemStatus
		if err := rows.Scan(&s.DeviceID, &s.Hostname, &s.ItemKind, &s.ItemID,
			&s.Status, &s.Detail, &s.Version, &s.UpdatedAt, &total); err != nil {
			return nil, 0, err
		}
		out = append(out, s)
	}
	return out, total, rows.Err()
}
