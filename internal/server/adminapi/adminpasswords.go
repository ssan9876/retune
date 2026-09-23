package adminapi

import (
	"errors"
	"net/http"
	"time"

	"retune/internal/server/laps"
	"retune/internal/server/store"
)

// adminPasswordJSON describes an escrowed local admin password, never the
// password itself.
type adminPasswordJSON struct {
	ID          string     `json:"id"`
	DeviceID    string     `json:"device_id"`
	Hostname    string     `json:"hostname"`
	Account     string     `json:"account"`
	State       string     `json:"state"`
	CommandID   string     `json:"command_id"`
	CreatedAt   time.Time  `json:"created_at"`
	ActivatedAt *time.Time `json:"activated_at,omitempty"`
}

func newAdminPasswordJSON(p store.AdminPassword) adminPasswordJSON {
	return adminPasswordJSON{
		ID: p.ID.String(), DeviceID: p.DeviceID.String(), Hostname: p.Hostname, Account: p.Account,
		State: p.State, CommandID: p.CommandID.String(), CreatedAt: p.CreatedAt, ActivatedAt: p.ActivatedAt,
	}
}

func (h *Handler) listAdminPasswords(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such device")
	if !ok {
		return
	}
	if !h.deviceVisible(w, r, id) {
		return
	}
	rows, err := h.LAPS.List(r.Context(), id)
	if err != nil {
		h.internal(w, "list admin passwords", err)
		return
	}
	items := make([]adminPasswordJSON, 0, len(rows))
	for _, p := range rows {
		items = append(items, newAdminPasswordJSON(p))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// revealAdminPassword hands back one local admin password, with a reason,
// on the record. Unlike a BitLocker key the reason is required: this is the
// key to a machine's administrator account, not to a locked-out laptop.
func (h *Handler) revealAdminPassword(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such password")
	if !ok {
		return
	}
	var req revealRequest
	if !decode(w, r, &req) {
		return
	}
	stored, err := h.LAPS.Get(r.Context(), id)
	if errors.Is(err, laps.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "no such password")
		return
	}
	if err != nil {
		h.internal(w, "get admin password", err)
		return
	}
	if visible, err := h.Store.Q().DeviceInScope(r.Context(), store.DefaultTenantID, stored.DeviceID, caller(r).Scope); err != nil {
		h.internal(w, "check device scope", err)
		return
	} else if !visible {
		writeError(w, http.StatusNotFound, "not_found", "no such password")
		return
	}
	p, password, err := h.LAPS.Reveal(r.Context(), id, caller(r).Admin.Email, req.Reason)
	switch {
	case err == nil:
	case errors.Is(err, laps.ErrBadRequest):
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	case errors.Is(err, laps.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such password")
		return
	default:
		h.internal(w, "reveal admin password", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"password": password, "admin_password": newAdminPasswordJSON(p)})
}
