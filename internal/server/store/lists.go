package store

import (
	"context"

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
	Search string
	Status string
	Page   Page
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
		ORDER BY lower(hostname), enrolled_at
		LIMIT $3 OFFSET $4`, f.Status, f.Search, p.Limit, p.Offset, DefaultTenantID)
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
}

// ListCommandsPage returns one page of commands, newest first, and the total.
func (q *Queries) ListCommandsPage(ctx context.Context, f CommandFilter) ([]Command, int, error) {
	p := f.Page.Normalized()
	rows, err := q.db.Query(ctx, `
		SELECT `+commandCols+`, count(*) OVER () AS total FROM commands
		WHERE tenant_id = $5 AND ($1::uuid IS NULL OR device_id = $1)
		  AND ($2 = '' OR status = $2)
		ORDER BY created_at DESC, id DESC
		LIMIT $3 OFFSET $4`, f.DeviceID, f.Status, p.Limit, p.Offset, DefaultTenantID)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []Command
	total := 0
	for rows.Next() {
		var c Command
		if err := rows.Scan(&c.ID, &c.DeviceID, &c.Type, &c.Payload, &c.Status, &c.CreatedBy, &c.CreatedAt,
			&c.DeliveredAt, &c.StartedAt, &c.CompletedAt, &c.ExpiresAt, &total); err != nil {
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

// ListAuditPage returns one page of audit entries, newest first, and the total.
func (q *Queries) ListAuditPage(ctx context.Context, page Page) ([]AuditEntry, int, error) {
	p := page.Normalized()
	rows, err := q.db.Query(ctx, `
		SELECT actor, action, target_kind, target_id, details, at, count(*) OVER () AS total
		FROM audit_log WHERE tenant_id = $3 ORDER BY at DESC, id DESC LIMIT $1 OFFSET $2`, p.Limit, p.Offset, DefaultTenantID)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []AuditEntry
	total := 0
	for rows.Next() {
		var a AuditEntry
		var raw []byte
		if err := rows.Scan(&a.Actor, &a.Action, &a.TargetKind, &a.TargetID, &raw, &a.At, &total); err != nil {
			return nil, 0, err
		}
		if err := unmarshalDetails(raw, &a); err != nil {
			return nil, 0, err
		}
		out = append(out, a)
	}
	return out, total, rows.Err()
}
