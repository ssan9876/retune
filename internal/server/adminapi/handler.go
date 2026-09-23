// Package adminapi serves the console's REST API.
package adminapi

import (
	"context"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"retune/internal/server/agentversions"
	"retune/internal/server/alerts"
	"retune/internal/server/apps"
	"retune/internal/server/auth"
	"retune/internal/server/bitlocker"
	"retune/internal/server/commands"
	"retune/internal/server/compliance"
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
	Auth          *auth.Service
	Store         *store.Store
	Commands      *commands.Service
	Devices       *devices.Service
	Groups        *groups.Service
	Scripts       *scripts.Service
	Profiles      *profiles.Service
	Apps          *apps.Service
	Compliance    *compliance.Service
	Alerts        *alerts.Service
	AgentVersions *agentversions.Service
	BitLocker     *bitlocker.Service
	Enroll        *enroll.Service
	// SSO is nil when single sign-on is not configured.
	SSO *auth.OIDC
	// SSOName is the sign-in button's text.
	SSOName string
	Now     func() time.Time
	Log     *slog.Logger
}

type authKey struct{}

// authContext is who is making this request: a signed-in admin with a
// session, or an API token standing in for one. For a token, Admin is a
// stand-in carrying the token's role and an "api-token:<name>" email, which
// is what the audit log records as the actor; Session is empty.
type authContext struct {
	Admin   store.Admin
	Session store.Session
	Token   *store.APIToken
}

// authSourceAPIToken marks the stand-in Admin of a token-authenticated
// request. It is never stored.
const authSourceAPIToken = "api_token"

func caller(r *http.Request) authContext { return r.Context().Value(authKey{}).(authContext) }

// Routes returns the admin API mux.
func (h *Handler) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	const base = "/api/admin/v1"

	mux.HandleFunc("GET "+base+"/setup", h.setup)
	mux.HandleFunc("POST "+base+"/session", h.login)
	mux.HandleFunc("GET "+base+"/oidc/start", h.oidcStart)
	mux.HandleFunc("GET "+base+"/oidc/callback", h.oidcCallback)
	mux.Handle("GET "+base+"/session", h.readSession(h.currentSession))
	mux.Handle("DELETE "+base+"/session", h.readSession(h.logout))

	h.mountResources(mux, base)
	return mux
}

// read allows both roles; write requires the admin role. Both accept a
// session or an API token.
func (h *Handler) read(next http.HandlerFunc) http.Handler  { return h.protect(next, false, true) }
func (h *Handler) write(next http.HandlerFunc) http.Handler { return h.protect(next, true, true) }

// readSession and writeSession are read and write for what only a person at
// a console should do: manage admins and API tokens, reveal a recovery key,
// look at their own session. An API token is refused here, so one that leaks
// cannot make more tokens or accounts to outlive its own revocation, or read
// out secrets in bulk.
func (h *Handler) readSession(next http.HandlerFunc) http.Handler {
	return h.protect(next, false, false)
}
func (h *Handler) writeSession(next http.HandlerFunc) http.Handler {
	return h.protect(next, true, false)
}

// protect authenticates the caller - an API token in the Authorization
// header, else the session cookie - enforces CSRF on a session's unsafe
// methods, and checks the role.
func (h *Handler) protect(next http.HandlerFunc, needsAdmin, allowToken bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A request that sends an Authorization header is judged on it alone,
		// never on a cookie that happens to ride along with it.
		if header := r.Header.Get("Authorization"); header != "" {
			h.withToken(w, r, header, next, needsAdmin, allowToken)
			return
		}
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

// withToken authenticates an API token. It needs no CSRF check: the header
// is something a script sets on purpose, never something a browser attaches
// to a request another site made it send.
func (h *Handler) withToken(w http.ResponseWriter, r *http.Request, header string, next http.HandlerFunc, needsAdmin, allowToken bool) {
	plain, ok := strings.CutPrefix(header, "Bearer ")
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthenticated", "use Authorization: Bearer <API token>")
		return
	}
	tok, err := h.Auth.AuthenticateAPIToken(r.Context(), strings.TrimSpace(plain))
	switch {
	case errors.Is(err, auth.ErrInvalidToken):
		writeError(w, http.StatusUnauthorized, "invalid_token", "the API token is invalid, expired or revoked")
		return
	case err != nil:
		h.internal(w, "authenticate API token", err)
		return
	}
	if !allowToken {
		writeError(w, http.StatusForbidden, "session_required", "this needs an admin signed in to the console; an API token cannot do it")
		return
	}
	if needsAdmin && tok.Role != store.RoleAdmin {
		writeError(w, http.StatusForbidden, "forbidden", "this token may only read")
		return
	}
	admin := store.Admin{ID: tok.ID, Email: "api-token:" + tok.Name, Role: tok.Role, AuthSource: authSourceAPIToken}
	next(w, r.WithContext(context.WithValue(r.Context(), authKey{}, authContext{Admin: admin, Token: &tok})))
}

func (h *Handler) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: SessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
}

// log is the one place the handler's optional logger is resolved, matching
// how every service layer treats its own Log field: a Handler built without
// one (a test, a caller that only wants the mux) still logs somewhere rather
// than panicking on the first error it has to report.
func (h *Handler) log() *slog.Logger {
	if h.Log != nil {
		return h.Log
	}
	return slog.Default()
}

func (h *Handler) internal(w http.ResponseWriter, msg string, err error, args ...any) {
	h.log().Error(msg, append([]any{"error", err}, args...)...)
	writeError(w, http.StatusInternalServerError, "internal", "internal server error")
}
