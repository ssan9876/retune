package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// AuditCursor is how far one audit destination has been sent.
type AuditCursor struct {
	LastAt time.Time
	LastID uuid.UUID
}

// GetAuditCursor returns a destination's cursor, and false if it has none
// yet - a destination seen for the first time.
func (q *Queries) GetAuditCursor(ctx context.Context, sink string) (AuditCursor, bool, error) {
	var c AuditCursor
	err := q.db.QueryRow(ctx,
		`SELECT last_at, last_id FROM audit_stream_cursors WHERE tenant_id = $1 AND sink = $2`,
		DefaultTenantID, sink).Scan(&c.LastAt, &c.LastID)
	if errors.Is(err, pgx.ErrNoRows) {
		return AuditCursor{}, false, nil
	}
	return c, err == nil, err
}

// SetAuditCursor records how far a destination has been sent.
func (q *Queries) SetAuditCursor(ctx context.Context, sink string, c AuditCursor, now time.Time) error {
	_, err := q.db.Exec(ctx, `
		INSERT INTO audit_stream_cursors (tenant_id, sink, last_at, last_id, updated_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (tenant_id, sink) DO UPDATE
		SET last_at = EXCLUDED.last_at, last_id = EXCLUDED.last_id, updated_at = EXCLUDED.updated_at`,
		DefaultTenantID, sink, c.LastAt, c.LastID, now)
	return err
}

// AuditAfter returns up to limit entries after the cursor and before before,
// oldest first: the next batch for a destination.
func (q *Queries) AuditAfter(ctx context.Context, c AuditCursor, before time.Time, limit int) ([]AuditEntry, error) {
	rows, err := q.db.Query(ctx, `
		SELECT id, actor, action, target_kind, target_id, details, at FROM audit_log
		WHERE tenant_id = $1 AND (at, id) > ($2, $3) AND at < $4
		ORDER BY at, id LIMIT $5`, DefaultTenantID, c.LastAt, c.LastID, before, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var a AuditEntry
		var raw []byte
		if err := rows.Scan(&a.ID, &a.Actor, &a.Action, &a.TargetKind, &a.TargetID, &raw, &a.At); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, &a.Details); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
