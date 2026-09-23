package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

func (q *Queries) InsertAudit(ctx context.Context, a AuditEntry) error {
	details := a.Details
	if details == nil {
		details = map[string]any{}
	}
	b, err := json.Marshal(details)
	if err != nil {
		return fmt.Errorf("marshal audit details: %w", err)
	}
	// At is normally left zero, for the database's clock; tests set it.
	var at *time.Time
	if !a.At.IsZero() {
		at = &a.At
	}
	id, err := uuid.NewV7()
	if err != nil {
		return err
	}
	_, err = q.db.Exec(ctx, `
		INSERT INTO audit_log (id, tenant_id, actor, action, target_kind, target_id, details, at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, COALESCE($8, now()))`,
		id, DefaultTenantID, a.Actor, a.Action, a.TargetKind, a.TargetID, b, at)
	return err
}

// ListAudit returns the newest entries first.
func (q *Queries) ListAudit(ctx context.Context, limit int) ([]AuditEntry, error) {
	rows, err := q.db.Query(ctx, `
		SELECT actor, action, target_kind, target_id, details, at
		FROM audit_log WHERE tenant_id = $2 ORDER BY at DESC, id DESC LIMIT $1`, limit, DefaultTenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var a AuditEntry
		var raw []byte
		if err := rows.Scan(&a.Actor, &a.Action, &a.TargetKind, &a.TargetID, &raw, &a.At); err != nil {
			return nil, err
		}
		if err := unmarshalDetails(raw, &a); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// unmarshalDetails decodes an audit entry's JSONB details column.
func unmarshalDetails(raw []byte, a *AuditEntry) error {
	if err := json.Unmarshal(raw, &a.Details); err != nil {
		return fmt.Errorf("unmarshal audit details: %w", err)
	}
	return nil
}
