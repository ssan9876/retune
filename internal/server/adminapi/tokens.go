package adminapi

import (
	"errors"
	"net/http"
	"time"

	"retune/internal/server/enroll"
	"retune/internal/server/store"
)

type createTokenRequest struct {
	Label      string `json:"label"`
	MaxUses    *int   `json:"max_uses"`
	ExpiresInH int    `json:"expires_in_hours"`
	// RegisteredOnly enrolls only devices registered by serial number.
	RegisteredOnly bool `json:"registered_only"`
}

func (h *Handler) createToken(w http.ResponseWriter, r *http.Request) {
	var req createTokenRequest
	if !decode(w, r, &req) {
		return
	}
	opts := enroll.TokenOptions{Label: req.Label, MaxUses: req.MaxUses, CreatedBy: caller(r).Admin.Email, RegisteredOnly: req.RegisteredOnly}
	if req.ExpiresInH > 0 {
		exp := h.Now().Add(time.Duration(req.ExpiresInH) * time.Hour)
		opts.ExpiresAt = &exp
	}
	plain, tok, err := h.Enroll.CreateToken(r.Context(), opts)
	switch {
	case err == nil:
	case errors.Is(err, enroll.ErrBadRequest):
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	default:
		h.internal(w, "create enrollment token", err)
		return
	}
	writeJSON(w, http.StatusCreated, createdEnrollmentToken{
		ID: tok.ID.String(), Token: plain, Label: tok.Label,
		MaxUses: tok.MaxUses, ExpiresAt: tok.ExpiresAt, CreatedAt: tok.CreatedAt, RegisteredOnly: tok.RegisteredOnly,
	})
}

type tokenJSON struct {
	ID        string     `json:"id"`
	Label     string     `json:"label"`
	MaxUses   *int       `json:"max_uses,omitempty"`
	UseCount  int        `json:"use_count"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	CreatedBy string     `json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
	// RegisteredOnly enrolls only devices registered by serial number.
	RegisteredOnly bool `json:"registered_only"`
}

func (h *Handler) listTokens(w http.ResponseWriter, r *http.Request) {
	rows, err := h.Store.Q().ListEnrollmentTokens(r.Context())
	if err != nil {
		h.internal(w, "list enrollment tokens", err)
		return
	}
	items := make([]tokenJSON, 0, len(rows))
	for _, t := range rows {
		items = append(items, tokenJSON{
			ID: t.ID.String(), Label: t.Label, MaxUses: t.MaxUses, UseCount: t.UseCount,
			ExpiresAt: t.ExpiresAt, RevokedAt: t.RevokedAt, CreatedBy: t.CreatedBy, CreatedAt: t.CreatedAt,
			RegisteredOnly: t.RegisteredOnly,
		})
	}
	writeJSON(w, http.StatusOK, newListResponse(items, len(items), store.Page{Limit: len(items)}))
}

func (h *Handler) revokeToken(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such token")
	if !ok {
		return
	}
	err := h.Enroll.RevokeToken(r.Context(), id, caller(r).Admin.Email)
	switch {
	case err == nil:
		writeNoContent(w)
	case errors.Is(err, enroll.ErrTokenNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such token")
	default:
		h.internal(w, "revoke enrollment token", err, "token_id", id)
	}
}
