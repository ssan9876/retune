package adminapi

import (
	"errors"
	"net/http"

	"github.com/google/uuid"

	"retune/internal/server/auth"
	"retune/internal/server/store"
)

func (h *Handler) listAdmins(w http.ResponseWriter, r *http.Request) {
	rows, err := h.Auth.List(r.Context())
	if err != nil {
		h.internal(w, "list admins", err)
		return
	}
	items := make([]adminJSON, 0, len(rows))
	for _, a := range rows {
		scope, err := h.Store.Q().AdminScope(r.Context(), store.DefaultTenantID, a.ID)
		if err != nil {
			h.internal(w, "admin scope", err)
			return
		}
		items = append(items, newAdminJSON(a).withScope(scope))
	}
	writeJSON(w, http.StatusOK, newListResponse(items, len(items), store.Page{Limit: len(items)}))
}

func (h *Handler) createAdmin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if !decode(w, r, &req) {
		return
	}
	admin, err := h.Auth.CreateAdmin(r.Context(), auth.CreateAdminOptions{
		Email: req.Email, Password: req.Password, Role: req.Role, Actor: caller(r).Admin.Email,
	})
	switch {
	case err == nil:
		writeJSON(w, http.StatusCreated, newAdminJSON(admin))
	case errors.Is(err, auth.ErrBadRequest), errors.Is(err, auth.ErrWeakPassword):
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
	default:
		// A duplicate email trips the unique index.
		h.log().Warn("create admin failed", "error", err)
		writeError(w, http.StatusBadRequest, "bad_request", "could not create this admin; the email may already be in use")
	}
}

func (h *Handler) setAdminPassword(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such admin")
	if !ok {
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if !decode(w, r, &req) {
		return
	}
	err := h.Auth.SetPassword(r.Context(), id, req.Password, caller(r).Admin.Email)
	switch {
	case err == nil:
		writeNoContent(w)
	case errors.Is(err, auth.ErrWeakPassword):
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
	case errors.Is(err, auth.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such admin")
	default:
		h.internal(w, "set admin password", err, "admin_id", id)
	}
}

func (h *Handler) setAdminTOTP(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such admin")
	if !ok {
		return
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if !decode(w, r, &req) {
		return
	}
	actor := caller(r).Admin.Email
	if !req.Enabled {
		switch err := h.Auth.DisableTOTP(r.Context(), id, actor); {
		case err == nil:
			writeNoContent(w)
		case errors.Is(err, auth.ErrNotFound):
			writeError(w, http.StatusNotFound, "not_found", "no such admin")
		default:
			h.internal(w, "disable TOTP", err, "admin_id", id)
		}
		return
	}
	secret, url, err := h.Auth.EnableTOTP(r.Context(), id, actor)
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, map[string]string{"secret": secret, "otpauth_url": url})
	case errors.Is(err, auth.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such admin")
	default:
		h.internal(w, "enable TOTP", err, "admin_id", id)
	}
}

func (h *Handler) setAdminDisabled(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such admin")
	if !ok {
		return
	}
	var req struct {
		Disabled bool `json:"disabled"`
	}
	if !decode(w, r, &req) {
		return
	}
	err := h.Auth.SetDisabled(r.Context(), id, req.Disabled, caller(r).Admin.Email)
	switch {
	case err == nil:
		writeNoContent(w)
	case errors.Is(err, auth.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such admin")
	case errors.Is(err, auth.ErrLastAdmin):
		writeError(w, http.StatusConflict, "last_admin", err.Error())
	default:
		h.internal(w, "set admin disabled", err, "admin_id", id)
	}
}

// setAdminScope limits an admin to device groups ({"group_ids": [...]}) or
// lifts the limit ({"group_ids": null}).
func (h *Handler) setAdminScope(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such admin")
	if !ok {
		return
	}
	var req struct {
		GroupIDs *[]string `json:"group_ids"`
	}
	if !decode(w, r, &req) {
		return
	}
	var groups []uuid.UUID
	if req.GroupIDs != nil {
		groups = make([]uuid.UUID, 0, len(*req.GroupIDs))
		for _, raw := range *req.GroupIDs {
			g, err := uuid.Parse(raw)
			if err != nil {
				writeError(w, http.StatusBadRequest, "bad_request", "group_ids must be group IDs")
				return
			}
			groups = append(groups, g)
		}
	}
	err := h.Auth.SetScope(r.Context(), id, groups, caller(r).Admin.Email)
	switch {
	case err == nil:
		writeNoContent(w)
	case errors.Is(err, auth.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such admin")
	case errors.Is(err, auth.ErrBadRequest):
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
	case errors.Is(err, auth.ErrLastAdmin):
		writeError(w, http.StatusConflict, "last_admin", err.Error())
	default:
		h.internal(w, "set admin scope", err)
	}
}
