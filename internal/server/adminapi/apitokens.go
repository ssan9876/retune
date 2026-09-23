package adminapi

import (
	"errors"
	"net/http"
	"time"

	"retune/internal/server/auth"
	"retune/internal/server/store"
)

type apiTokenJSON struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Role       string     `json:"role"`
	CreatedBy  string     `json:"created_by"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

func newAPITokenJSON(t store.APIToken) apiTokenJSON {
	return apiTokenJSON{
		ID: t.ID.String(), Name: t.Name, Role: t.Role, CreatedBy: t.CreatedBy,
		CreatedAt: t.CreatedAt, ExpiresAt: t.ExpiresAt, LastUsedAt: t.LastUsedAt, RevokedAt: t.RevokedAt,
	}
}

func (h *Handler) listAPITokens(w http.ResponseWriter, r *http.Request) {
	tokens, err := h.Auth.ListAPITokens(r.Context())
	if err != nil {
		h.internal(w, "list API tokens", err)
		return
	}
	items := make([]apiTokenJSON, 0, len(tokens))
	for _, t := range tokens {
		items = append(items, newAPITokenJSON(t))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": len(items)})
}

// createAPIToken returns the token itself once, in this response, and never
// again: only its hash is kept.
func (h *Handler) createAPIToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
		Role string `json:"role"`
		Days int    `json:"expires_in_days"`
	}
	if !decode(w, r, &req) {
		return
	}
	plain, tok, err := h.Auth.CreateAPIToken(r.Context(), auth.NewAPIToken{
		Name: req.Name, Role: req.Role, Days: req.Days, Creator: caller(r).Admin,
	})
	switch {
	case err == nil:
	case errors.Is(err, auth.ErrBadRequest):
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	case errors.Is(err, auth.ErrDuplicateToken):
		writeError(w, http.StatusConflict, "duplicate", err.Error())
		return
	default:
		h.internal(w, "create API token", err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"token": plain, "api_token": newAPITokenJSON(tok)})
}

func (h *Handler) revokeAPIToken(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such API token")
	if !ok {
		return
	}
	err := h.Auth.RevokeAPIToken(r.Context(), id, caller(r).Admin.Email)
	switch {
	case err == nil:
		writeNoContent(w)
	case errors.Is(err, auth.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such API token")
	default:
		h.internal(w, "revoke API token", err)
	}
}
