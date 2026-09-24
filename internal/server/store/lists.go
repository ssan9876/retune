package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Paging defaults.
const (
	DefaultPageLimit = 50
	MaxPageLimit     = 200
)

// Page is a limit/offset window.
type Page struct {
	Limit  int
	Offset int
}

// Normalized clamps a page into the supported range.
func (p Page) Normalized() Page {
	if p.Limit <= 0 {
		p.Limit = DefaultPageLimit
	}
	if p.Limit > MaxPageLimit {
		p.Limit = MaxPageLimit
	}
	if p.Offset < 0 {
		p.Offset = 0
	}
	return p
}

// DeviceFilter narrows a device listing. Search matches hostname, serial,
// SMBIOS UUID, manufacturer and model.
type DeviceFilter struct {
	Search      string
	Status      string
	Bucket      string
	StaleCutoff time.Time
	Compliance  string
	Page        Page
	Scope       DeviceScope
}

// ListDevicesPage returns one page of devices and the total number of matches.
func (q *Queries) ListDevicesPage(ctx context.Context, f DeviceFilter) ([]Device, int, error) {
	p := f.Page.Normalized()
	rows, err := q.db.Query(ctx, `
		SELECT `+deviceCols+`, count(*) OVER () AS total FROM devices
		WHERE tenant_id = $5 AND ($1 = '' OR status = $1)
		  AND ($2 = '' OR hostname ILIKE '%' || $2 || '%' OR serial ILIKE '%' || $2 || '%'
		       OR smbios_uuid ILIKE '%' || $2 || '%' OR manufacturer ILIKE '%' || $2 || '%'
		       OR model ILIKE '%' || $2 || '%')
		  AND `+scopeSQL("id", 6)+`
		  AND ($7 = ''
		       OR ($7 = 'active' AND status = 'active' AND last_seen_at >= $8)
		       OR ($7 = 'stale' AND status = 'active' AND (last_seen_at IS NULL OR last_seen_at < $8))
		       OR ($7 = 'retired' AND status <> 'active'))
		  AND ($9 = '' OR $9 = COALESCE((
			SELECT CASE max(CASE dc.state
				WHEN 'compliant' THEN 0
				WHEN 'unknown' THEN 1
				WHEN 'non_compliant' THEN 2
			END)
				WHEN 0 THEN 'compliant'
				WHEN 1 THEN 'unknown'
				WHEN 2 THEN 'non_compliant'
			END
			FROM device_compliance dc
			WHERE dc.tenant_id = devices.tenant_id AND dc.device_id = devices.id
		  ), 'not_evaluated'))
		ORDER BY lower(hostname), enrolled_at
		LIMIT $3 OFFSET $4`, f.Status, f.Search, p.Limit, p.Offset, DefaultTenantID, f.Scope.arg(),
		f.Bucket, f.StaleCutoff, f.Compliance)
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

// CommandFilter narrows a command listing.
type CommandFilter struct {
	DeviceID *uuid.UUID
	Status   string
	Page     Page
	Scope    DeviceScope
}

// ListCommandsPage returns one page of commands, newest first, and the total.
func (q *Queries) ListCommandsPage(ctx context.Context, f CommandFilter) ([]Command, int, error) {
	p := f.Page.Normalized()
	rows, err := q.db.Query(ctx, `
		SELECT c.id, c.device_id, c.type, c.payload, c.status, c.created_by, c.created_at,
		       c.delivered_at, c.started_at, c.completed_at, c.expires_at, d.hostname,
		       count(*) OVER () AS total
		FROM commands c
		JOIN devices d ON d.tenant_id = c.tenant_id AND d.id = c.device_id
		WHERE c.tenant_id = $5 AND ($1::uuid IS NULL OR c.device_id = $1)
		  AND ($2 = '' OR c.status = $2) AND `+scopeSQL("c.device_id", 6)+`
		ORDER BY c.created_at DESC, c.id DESC
		LIMIT $3 OFFSET $4`, f.DeviceID, f.Status, p.Limit, p.Offset, DefaultTenantID, f.Scope.arg())
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []Command
	total := 0
	for rows.Next() {
		var c Command
		if err := rows.Scan(&c.ID, &c.DeviceID, &c.Type, &c.Payload, &c.Status, &c.CreatedBy, &c.CreatedAt,
			&c.DeliveredAt, &c.StartedAt, &c.CompletedAt, &c.ExpiresAt, &c.Hostname, &total); err != nil {
			return nil, 0, err
		}
		out = append(out, c)
	}
	return out, total, rows.Err()
}

// ListEnrollmentTokens returns every token, newest first.
func (q *Queries) ListEnrollmentTokens(ctx context.Context) ([]EnrollmentToken, error) {
	rows, err := q.db.Query(ctx, `SELECT `+tokenCols+` FROM enrollment_tokens WHERE tenant_id = $1 ORDER BY created_at DESC, id DESC`,
		DefaultTenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EnrollmentToken
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// AuditFilter narrows the audit log. Actor and Action match a substring,
// case-insensitively; Since and Until bound the time, either left zero for
// no bound.
type AuditFilter struct {
	Actor  string
	Action string
	Since  time.Time
	Until  time.Time
	Page   Page
}

// ListAuditPage returns one page of audit entries, newest first, and the total.
func (q *Queries) ListAuditPage(ctx context.Context, f AuditFilter) ([]AuditEntry, int, error) {
	p := f.Page.Normalized()
	var since, until *time.Time
	if !f.Since.IsZero() {
		since = &f.Since
	}
	if !f.Until.IsZero() {
		until = &f.Until
	}
	rows, err := q.db.Query(ctx, `
		SELECT id, actor, action, target_kind, target_id, details, at, count(*) OVER () AS total
		FROM audit_log
		WHERE tenant_id = $3
		  AND ($4 = '' OR actor ILIKE '%' || $4 || '%')
		  AND ($5 = '' OR action ILIKE '%' || $5 || '%')
		  AND ($6::timestamptz IS NULL OR at >= $6)
		  AND ($7::timestamptz IS NULL OR at < $7)
		ORDER BY at DESC, id DESC LIMIT $1 OFFSET $2`,
		p.Limit, p.Offset, DefaultTenantID, f.Actor, f.Action, since, until)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []AuditEntry
	total := 0
	for rows.Next() {
		var a AuditEntry
		var raw []byte
		if err := rows.Scan(&a.ID, &a.Actor, &a.Action, &a.TargetKind, &a.TargetID, &raw, &a.At, &total); err != nil {
			return nil, 0, err
		}
		if err := json.Unmarshal(raw, &a.Details); err != nil {
			return nil, 0, err
		}
		out = append(out, a)
	}
	return out, total, rows.Err()
}
