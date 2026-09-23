package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// MaintenanceWindow is when the devices it is assigned to may be changed.
// Schedule is a protocol.Window, stored and sent as JSON.
type MaintenanceWindow struct {
	ID          uuid.UUID
	Name        string
	Description string
	Schedule    []byte
	CreatedAt   time.Time
	UpdatedAt   time.Time
	CreatedBy   string
}

const windowCols = `id, name, description, schedule, created_at, updated_at, created_by`

func scanWindow(row pgx.Row) (MaintenanceWindow, error) {
	var w MaintenanceWindow
	err := row.Scan(&w.ID, &w.Name, &w.Description, &w.Schedule, &w.CreatedAt, &w.UpdatedAt, &w.CreatedBy)
	return w, notFound(err)
}

// CreateMaintenanceWindow stores a window; a name already taken, in any case,
// is ErrDuplicate.
func (q *Queries) CreateMaintenanceWindow(ctx context.Context, w MaintenanceWindow) error {
	_, err := q.db.Exec(ctx, `
		INSERT INTO maintenance_windows (id, tenant_id, name, description, schedule, created_at, updated_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $6, $7)`,
		w.ID, DefaultTenantID, w.Name, w.Description, w.Schedule, w.CreatedAt, w.CreatedBy)
	return duplicate(err)
}

// GetMaintenanceWindow looks up one window.
func (q *Queries) GetMaintenanceWindow(ctx context.Context, id uuid.UUID) (MaintenanceWindow, error) {
	return scanWindow(q.db.QueryRow(ctx,
		`SELECT `+windowCols+` FROM maintenance_windows WHERE tenant_id = $1 AND id = $2`, DefaultTenantID, id))
}

// ListMaintenanceWindows returns every window, by name. There are few.
func (q *Queries) ListMaintenanceWindows(ctx context.Context) ([]MaintenanceWindow, error) {
	rows, err := q.db.Query(ctx,
		`SELECT `+windowCols+` FROM maintenance_windows WHERE tenant_id = $1 ORDER BY lower(name)`, DefaultTenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MaintenanceWindow
	for rows.Next() {
		w, err := scanWindow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// UpdateMaintenanceWindow replaces a window's name, description and schedule.
func (q *Queries) UpdateMaintenanceWindow(ctx context.Context, w MaintenanceWindow) error {
	tag, err := q.db.Exec(ctx, `
		UPDATE maintenance_windows SET name = $3, description = $4, schedule = $5, updated_at = $6
		WHERE tenant_id = $1 AND id = $2`,
		DefaultTenantID, w.ID, w.Name, w.Description, w.Schedule, w.UpdatedAt)
	if err != nil {
		return duplicate(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteMaintenanceWindow removes a window and its assignments.
func (q *Queries) DeleteMaintenanceWindow(ctx context.Context, id uuid.UUID) error {
	if err := q.DeleteAssignmentsForItem(ctx, "window", id); err != nil {
		return err
	}
	tag, err := q.db.Exec(ctx, `DELETE FROM maintenance_windows WHERE tenant_id = $1 AND id = $2`, DefaultTenantID, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
