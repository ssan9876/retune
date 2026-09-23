package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"retune/internal/protocol"
	"retune/internal/server/store"
)

type windowJSON struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Days        []string  `json:"days"`
	Start       string    `json:"start"`
	Duration    int       `json:"duration_minutes"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	CreatedBy   string    `json:"created_by"`
}

func newWindowJSON(w store.MaintenanceWindow) windowJSON {
	var sched protocol.Window
	// Written by windowFromRequest, so it parses; a zero schedule is what a
	// row that somehow doesn't would show.
	_ = json.Unmarshal(w.Schedule, &sched)
	days := sched.Days
	if days == nil {
		days = []string{}
	}
	return windowJSON{
		ID: w.ID.String(), Name: w.Name, Description: w.Description,
		Days: days, Start: sched.Start, Duration: sched.DurationMinutes,
		CreatedAt: w.CreatedAt, UpdatedAt: w.UpdatedAt, CreatedBy: w.CreatedBy,
	}
}

type windowRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Days        []string `json:"days"`
	Start       string   `json:"start"`
	Duration    int      `json:"duration_minutes"`
}

// windowFromRequest checks a request and builds the window it describes.
func windowFromRequest(req windowRequest) (name string, schedule []byte, err error) {
	name = strings.TrimSpace(req.Name)
	if name == "" || len(name) > 200 {
		return "", nil, errors.New("name is required, at most 200 characters")
	}
	if len(req.Description) > 2000 {
		return "", nil, errors.New("description must be at most 2000 characters")
	}
	w := protocol.Window{Days: req.Days, Start: strings.TrimSpace(req.Start), DurationMinutes: req.Duration}
	if err := w.Validate(); err != nil {
		return "", nil, errors.New(strings.TrimPrefix(err.Error(), protocol.ErrBadOptions.Error()+": "))
	}
	schedule, err = json.Marshal(w)
	return name, schedule, err
}

func (h *Handler) listWindows(w http.ResponseWriter, r *http.Request) {
	rows, err := h.Store.Q().ListMaintenanceWindows(r.Context())
	if err != nil {
		h.internal(w, "list maintenance windows", err)
		return
	}
	items := make([]windowJSON, 0, len(rows))
	for _, row := range rows {
		items = append(items, newWindowJSON(row))
	}
	writeJSON(w, http.StatusOK, newListResponse(items, len(items), store.Page{Limit: len(items)}))
}

func (h *Handler) getWindow(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such maintenance window")
	if !ok {
		return
	}
	row, err := h.Store.Q().GetMaintenanceWindow(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "no such maintenance window")
		return
	} else if err != nil {
		h.internal(w, "get maintenance window", err)
		return
	}
	writeJSON(w, http.StatusOK, newWindowJSON(row))
}

func (h *Handler) createWindow(w http.ResponseWriter, r *http.Request) {
	var req windowRequest
	if !decode(w, r, &req) {
		return
	}
	name, schedule, err := windowFromRequest(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	now := h.Now()
	row := store.MaintenanceWindow{
		ID: uuid.Must(uuid.NewV7()), Name: name, Description: req.Description, Schedule: schedule,
		CreatedAt: now, UpdatedAt: now, CreatedBy: caller(r).Admin.Email,
	}
	ctx := r.Context()
	err = h.Store.InTx(ctx, func(q *store.Queries) error {
		if err := q.CreateMaintenanceWindow(ctx, row); err != nil {
			return err
		}
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: row.CreatedBy, Action: "maintenance_window.created", TargetKind: "maintenance_window",
			TargetID: row.ID.String(), Details: map[string]any{"name": name, "schedule": json.RawMessage(schedule)},
		})
	})
	h.writeWindowResult(w, http.StatusCreated, row, err)
}

func (h *Handler) updateWindow(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such maintenance window")
	if !ok {
		return
	}
	var req windowRequest
	if !decode(w, r, &req) {
		return
	}
	name, schedule, err := windowFromRequest(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	ctx := r.Context()
	var row store.MaintenanceWindow
	err = h.Store.InTx(ctx, func(q *store.Queries) error {
		cur, err := q.GetMaintenanceWindow(ctx, id)
		if err != nil {
			return err
		}
		row = cur
		row.Name, row.Description, row.Schedule, row.UpdatedAt = name, req.Description, schedule, h.Now()
		if err := q.UpdateMaintenanceWindow(ctx, row); err != nil {
			return err
		}
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: caller(r).Admin.Email, Action: "maintenance_window.updated", TargetKind: "maintenance_window",
			TargetID: id.String(), Details: map[string]any{"name": name, "schedule": json.RawMessage(schedule)},
		})
	})
	h.writeWindowResult(w, http.StatusOK, row, err)
}

func (h *Handler) writeWindowResult(w http.ResponseWriter, status int, row store.MaintenanceWindow, err error) {
	switch {
	case err == nil:
		writeJSON(w, status, newWindowJSON(row))
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such maintenance window")
	case errors.Is(err, store.ErrDuplicate):
		writeError(w, http.StatusConflict, "duplicate", "a maintenance window with that name already exists")
	default:
		h.internal(w, "save maintenance window", err)
	}
}

func (h *Handler) deleteWindow(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such maintenance window")
	if !ok {
		return
	}
	ctx := r.Context()
	err := h.Store.InTx(ctx, func(q *store.Queries) error {
		cur, err := q.GetMaintenanceWindow(ctx, id)
		if err != nil {
			return err
		}
		if err := q.DeleteMaintenanceWindow(ctx, id); err != nil {
			return err
		}
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: caller(r).Admin.Email, Action: "maintenance_window.deleted", TargetKind: "maintenance_window",
			TargetID: id.String(), Details: map[string]any{"name": cur.Name},
		})
	})
	switch {
	case err == nil:
		writeNoContent(w)
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such maintenance window")
	default:
		h.internal(w, "delete maintenance window", err)
	}
}
