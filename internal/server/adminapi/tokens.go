package adminapi

import (
	"errors"
	"net/http"
	"time"

	"retune/internal/server/enroll"
)

type createTokenRequest struct {
	Label      string `json:"label"`
	MaxUses    *int   `json:"max_uses"`
	ExpiresInH int    `json:"expires_in_hours"`
}

func (h *Handler) createToken(w http.ResponseWriter, r *http.Request) {
	var req createTokenRequest
	if !decode(w, r, &req) {
		return
	}
	opts := enroll.TokenOptions{Label: req.Label, MaxUses: req.MaxUses, CreatedBy: caller(r).Admin.Email}
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
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": tok.ID.String(), "token": plain, "label": tok.Label,
		"max_uses": tok.MaxUses, "expires_at": tok.ExpiresAt, "created_at": tok.CreatedAt,
	})
}
