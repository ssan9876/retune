package store

import (
	"context"
	"encoding/json"
	"fmt"

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
	id, err := uuid.NewV7()
	if err != nil {
		return err
	}
	_, err = q.db.Exec(ctx, `
		INSERT INTO audit_log (id, tenant_id, actor, action, target_kind, target_id, details)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		id, DefaultTenantID, a.Actor, a.Action, a.TargetKind, a.TargetID, b)
	return err
}

// ListAudit returns the newest entries first.
func (q *Queries) ListAudit(ctx context.Context, limit int) ([]AuditEntry, error) {
	rows, err := q.db.Query(ctx, `
		SELECT actor, action, target_kind, target_id, details, at
		FROM audit_log ORDER BY at DESC, id DESC LIMIT $1`, limit)
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
		if err := json.Unmarshal(raw, &a.Details); err != nil {
			return nil, fmt.Errorf("unmarshal audit details: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
