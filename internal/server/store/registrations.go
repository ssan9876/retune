package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// DeviceRegistration is a device registered by serial number before it
// enrolls: the groups it joins and the name it gets when it does.
type DeviceRegistration struct {
	ID         uuid.UUID
	Serial     string
	DeviceName string
	GroupIDs   []uuid.UUID
	Notes      string
	DeviceID   *uuid.UUID
	EnrolledAt *time.Time
	CreatedAt  time.Time
	CreatedBy  string
}

const registrationCols = `id, serial, device_name, group_ids, notes, device_id, enrolled_at, created_at, created_by`

func scanRegistration(row pgx.Row) (DeviceRegistration, error) {
	var r DeviceRegistration
	err := row.Scan(&r.ID, &r.Serial, &r.DeviceName, &r.GroupIDs, &r.Notes, &r.DeviceID, &r.EnrolledAt, &r.CreatedAt, &r.CreatedBy)
	return r, notFound(err)
}

// CreateRegistration stores a registration; a serial already registered, in
// any case, is ErrDuplicate.
func (q *Queries) CreateRegistration(ctx context.Context, r DeviceRegistration) error {
	if r.GroupIDs == nil {
		r.GroupIDs = []uuid.UUID{}
	}
	_, err := q.db.Exec(ctx, `
		INSERT INTO device_registrations (id, tenant_id, serial, device_name, group_ids, notes, created_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		r.ID, DefaultTenantID, r.Serial, r.DeviceName, r.GroupIDs, r.Notes, r.CreatedAt, r.CreatedBy)
	return duplicate(err)
}

// GetRegistration looks up one registration.
func (q *Queries) GetRegistration(ctx context.Context, id uuid.UUID) (DeviceRegistration, error) {
	return scanRegistration(q.db.QueryRow(ctx,
		`SELECT `+registrationCols+` FROM device_registrations WHERE tenant_id = $1 AND id = $2`, DefaultTenantID, id))
}

// RegistrationForSerial finds the registration for a serial, ignoring case,
// locking it for the enrollment that found it.
func (q *Queries) RegistrationForSerial(ctx context.Context, serial string) (DeviceRegistration, error) {
	return scanRegistration(q.db.QueryRow(ctx, `
		SELECT `+registrationCols+` FROM device_registrations
		WHERE tenant_id = $1 AND upper(serial) = upper($2) FOR UPDATE`, DefaultTenantID, serial))
}

// ListRegistrations returns one page of registrations, newest first.
func (q *Queries) ListRegistrations(ctx context.Context, page Page) ([]DeviceRegistration, int, error) {
	p := page.Normalized()
	rows, err := q.db.Query(ctx, `
		SELECT `+registrationCols+`, count(*) OVER () FROM device_registrations
		WHERE tenant_id = $1 ORDER BY created_at DESC, id DESC LIMIT $2 OFFSET $3`,
		DefaultTenantID, p.Limit, p.Offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []DeviceRegistration
	total := 0
	for rows.Next() {
		var r DeviceRegistration
		if err := rows.Scan(&r.ID, &r.Serial, &r.DeviceName, &r.GroupIDs, &r.Notes, &r.DeviceID, &r.EnrolledAt,
			&r.CreatedAt, &r.CreatedBy, &total); err != nil {
			return nil, 0, err
		}
		out = append(out, r)
	}
	return out, total, rows.Err()
}

// MarkRegistrationEnrolled records which device a registration became.
func (q *Queries) MarkRegistrationEnrolled(ctx context.Context, id, deviceID uuid.UUID, at time.Time) error {
	_, err := q.db.Exec(ctx, `
		UPDATE device_registrations SET device_id = $3, enrolled_at = $4 WHERE tenant_id = $1 AND id = $2`,
		DefaultTenantID, id, deviceID, at)
	return err
}

// DeleteRegistration removes a registration.
func (q *Queries) DeleteRegistration(ctx context.Context, id uuid.UUID) error {
	tag, err := q.db.Exec(ctx, `DELETE FROM device_registrations WHERE tenant_id = $1 AND id = $2`, DefaultTenantID, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}
