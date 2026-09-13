// Package adminapi serves the console's REST API.
package adminapi

import (
	"context"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"retune/internal/server/apps"
	"retune/internal/server/auth"
	"retune/internal/server/bitlocker"
	"retune/internal/server/commands"
	"retune/internal/server/devices"
	"retune/internal/server/enroll"
	"retune/internal/server/groups"
	"retune/internal/server/profiles"
	"retune/internal/server/scripts"
	"retune/internal/server/store"
)

// SessionCookie holds the session token; CSRFHeader carries its CSRF token.
const (
	SessionCookie = "retune_session"
	CSRFHeader    = "X-CSRF-Token"
)

// Handler serves /api/admin/v1.
type Handler struct {
	Auth      *auth.Service
	Store     *store.Store
	Commands  *commands.Service
	Devices   *devices.Service
	Groups    *groups.Service
	Scripts   *scripts.Service
	Profiles  *profiles.Service
	Apps      *apps.Service
	BitLocker *bitlocker.Service
	Enroll    *enroll.Service
	Now       func() time.Time
	Log       *slog.Logger
}

type authKey struct{}

// authContext is the signed-in admin for this request.
type authContext struct {
	Admin   store.Admin
	Session store.Session
}

func caller(r *http.Request) authContext { return r.Context().Value(authKey{}).(authContext) }

// Routes returns the admin API mux.
func (h *Handler) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	const base = "/api/admin/v1"

	mux.HandleFunc("GET "+base+"/setup", h.setup)
	mux.HandleFunc("POST "+base+"/session", h.login)
	mux.Handle("GET "+base+"/session", h.read(h.currentSession))
	mux.Handle("DELETE "+base+"/session", h.read(h.logout))

	h.mountResources(mux, base)
	return mux
}

// read allows both roles; write requires the admin role.
func (h *Handler) read(next http.HandlerFunc) http.Handler  { return h.protect(next, false) }
func (h *Handler) write(next http.HandlerFunc) http.Handler { return h.protect(next, true) }

// protect authenticates the session cookie, enforces CSRF on unsafe methods and
// checks the role.
func (h *Handler) protect(next http.HandlerFunc, needsAdmin bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(SessionCookie)
		if err != nil || cookie.Value == "" {
			writeError(w, http.StatusUnauthorized, "unauthenticated", "sign in to continue")
			return
		}
		admin, session, err := h.Auth.ValidateSession(r.Context(), cookie.Value)
		switch {
		case errors.Is(err, auth.ErrInvalidSession):
			h.clearCookie(w)
			writeError(w, http.StatusUnauthorized, "unauthenticated", "sign in to continue")
			return
		case errors.Is(err, auth.ErrAccountDisabled):
			h.clearCookie(w)
			writeError(w, http.StatusForbidden, "account_disabled", "this account is disabled")
			return
		case err != nil:
			h.internal(w, "validate session", err)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			sent := r.Header.Get(CSRFHeader)
			if subtle.ConstantTimeCompare([]byte(sent), []byte(session.CSRFToken)) != 1 {
				writeError(w, http.StatusForbidden, "csrf_invalid", "missing or invalid CSRF token")
				return
			}
		}
		if needsAdmin && admin.Role != store.RoleAdmin {
			writeError(w, http.StatusForbidden, "forbidden", "this account may only read")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), authKey{}, authContext{Admin: admin, Session: session})))
	})
}

func (h *Handler) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: SessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
}

func (h *Handler) internal(w http.ResponseWriter, msg string, err error, args ...any) {
	h.Log.Error(msg, append([]any{"error", err}, args...)...)
	writeError(w, http.StatusInternalServerError, "internal", "internal server error")
}
