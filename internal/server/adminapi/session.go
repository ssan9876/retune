package adminapi

import (
	"errors"
	"net"
	"net/http"
	"time"

	"retune/internal/server/auth"
	"retune/internal/server/store"
)

// adminJSON is how an account appears in the API.
type adminJSON struct {
	ID          string     `json:"id"`
	Email       string     `json:"email"`
	Role        string     `json:"role"`
	TOTPEnabled bool       `json:"totp_enabled"`
	Disabled    bool       `json:"disabled"`
	CreatedAt   time.Time  `json:"created_at"`
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`
}

func newAdminJSON(a store.Admin) adminJSON {
	return adminJSON{
		ID: a.ID.String(), Email: a.Email, Role: a.Role,
		TOTPEnabled: a.TOTPSecret != "", Disabled: a.DisabledAt != nil,
		CreatedAt: a.CreatedAt, LastLoginAt: a.LastLoginAt,
	}
}

type sessionResponse struct {
	Admin     adminJSON `json:"admin"`
	CSRFToken string    `json:"csrf_token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// setup tells the console whether the first admin still has to be created.
func (h *Handler) setup(w http.ResponseWriter, r *http.Request) {
	has, err := h.Auth.HasAdmins(r.Context())
	if err != nil {
		h.internal(w, "count admins", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"needs_setup": !has})
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		TOTPCode string `json:"totp_code"`
	}
	if !decode(w, r, &req) {
		return
	}
	admin, err := h.Auth.Authenticate(r.Context(), req.Email, req.Password, req.TOTPCode)
	switch {
	case err == nil:
	case errors.Is(err, auth.ErrInvalidCredentials):
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "invalid email or password")
		return
	case errors.Is(err, auth.ErrTOTPRequired):
		writeError(w, http.StatusUnauthorized, "totp_required", "enter your authenticator code")
		return
	case errors.Is(err, auth.ErrTOTPInvalid):
		writeError(w, http.StatusUnauthorized, "totp_invalid", "invalid authenticator code")
		return
	case errors.Is(err, auth.ErrAccountDisabled):
		writeError(w, http.StatusForbidden, "account_disabled", "this account is disabled")
		return
	case errors.Is(err, auth.ErrTooManyAttempts):
		writeError(w, http.StatusTooManyRequests, "too_many_attempts", "too many failed attempts; try again later")
		return
	default:
		h.internal(w, "authenticate", err)
		return
	}

	info, err := h.Auth.CreateSession(r.Context(), admin.ID, r.UserAgent(), clientIP(r))
	if err != nil {
		h.internal(w, "create session", err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: SessionCookie, Value: info.Token, Path: "/",
		Expires: info.ExpiresAt, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
	writeJSON(w, http.StatusOK, sessionResponse{
		Admin: newAdminJSON(admin), CSRFToken: info.CSRFToken, ExpiresAt: info.ExpiresAt,
	})
}

func (h *Handler) currentSession(w http.ResponseWriter, r *http.Request) {
	c := caller(r)
	writeJSON(w, http.StatusOK, sessionResponse{
		Admin: newAdminJSON(c.Admin), CSRFToken: c.Session.CSRFToken, ExpiresAt: c.Session.ExpiresAt,
	})
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(SessionCookie)
	if err == nil {
		if err := h.Auth.DeleteSession(r.Context(), cookie.Value); err != nil {
			h.internal(w, "delete session", err)
			return
		}
	}
	h.clearCookie(w)
	writeNoContent(w)
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
