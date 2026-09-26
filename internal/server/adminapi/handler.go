// Package adminapi serves the console's REST API.
package adminapi

import (
	"context"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"

	"retune/internal/server/agentversions"
	"retune/internal/server/alerts"
	"retune/internal/server/apps"
	"retune/internal/server/attest"
	"retune/internal/server/auth"
	"retune/internal/server/bitlocker"
	"retune/internal/server/commands"
	"retune/internal/server/compliance"
	"retune/internal/server/devices"
	"retune/internal/server/enroll"
	"retune/internal/server/groups"
	"retune/internal/server/laps"
	"retune/internal/server/profiles"
	"retune/internal/server/remote"
	"retune/internal/server/reports"
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
	LAPS          *laps.Service
	Reports       *reports.Service
	Attest        *attest.Service
	Remote        *remote.Service
	Enroll        *enroll.Service
	// SSO is nil when single sign-on is not configured.
	SSO *auth.OIDC
	// SSOName is the sign-in button's text.
	SSOName string
	// SigningRequired is whether OPERATIONS_KEYS is set.
	SigningRequired bool
	// AgentDownloadURL is AGENT_DOWNLOAD_URL, shown on the Enrollment page.
	AgentDownloadURL string
	// ApprovalsRequired holds wipes, and code sent to more than
	// ApprovalThreshold devices, for a second administrator.
	ApprovalsRequired bool
	ApprovalThreshold int
	Now               func() time.Time
	// TrustedProxies may say, in X-Forwarded-For, where a request came from.
	TrustedProxies []netip.Prefix

	routes map[string]guarded
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
	// Scope limits which devices this request may see or touch; nil is the
	// whole fleet.
	Scope store.DeviceScope
}

// authSourceAPIToken marks the stand-in Admin of a token-authenticated
// request. It is never stored.
const authSourceAPIToken = "api_token"

func caller(r *http.Request) authContext { return r.Context().Value(authKey{}).(authContext) }

// Routes returns the admin API mux.
func (h *Handler) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	const base = "/api/admin/v1"

	h.handle(mux, "GET "+base+"/setup", public(h.setup))
	h.handle(mux, "POST "+base+"/session", public(h.login))
	h.handle(mux, "GET "+base+"/oidc/start", public(h.oidcStart))
	h.handle(mux, "GET "+base+"/oidc/callback", public(h.oidcCallback))
	h.handle(mux, "GET "+base+"/session", h.readSession(h.currentSession))
	h.handle(mux, "DELETE "+base+"/session", h.readSession(h.logout))

	h.mountResources(mux, base)
	return mux
}

// access says who may call a route. Every route is registered through one of
// the wrappers below, each of which fixes all three; routes_test.go lists the
// class every route is expected to have, so a new route has to be placed in
// one on purpose.
type access struct {
	// admin requires the admin role rather than read-only.
	admin bool
	// operate requires the admin or helpdesk role: the day-to-day device
	// actions a helpdesk takes.
	operate bool
	// session refuses API tokens: what only a person at a console should do.
	session bool
	// fleet refuses scoped admins: what concerns the whole fleet rather than
	// devices, so has no scoped form.
	fleet bool
}

// guarded is a route's handler together with its access class, so the class
// can be read back by the route-enumeration test.
type guarded struct {
	http.Handler
	access access
	// open marks the routes that need no sign-in at all.
	open bool
}

// public is a route anyone may call: setup, sign-in and the SSO redirects.
func public(next http.HandlerFunc) http.Handler { return guarded{Handler: next, open: true} }

// handle registers a route and remembers its class. Every route must come
// through here as a guarded handler; one that does not fails at startup, so a
// route cannot be added without deciding who may call it.
func (h *Handler) handle(mux *http.ServeMux, pattern string, handler http.Handler) {
	g, ok := handler.(guarded)
	if !ok {
		panic("adminapi: route " + pattern + " was registered without an access class")
	}
	if h.routes == nil {
		h.routes = map[string]guarded{}
	}
	h.routes[pattern] = g
	mux.Handle(pattern, g)
}

// read allows both roles and write requires admin; both accept a session or
// an API token, and a scoped admin, whose view the handler limits to their
// devices.
func (h *Handler) read(next http.HandlerFunc) http.Handler  { return h.protect(next, access{}) }
func (h *Handler) write(next http.HandlerFunc) http.Handler { return h.protect(next, access{admin: true}) }

// operate and operateSession allow admins and helpdesk: device actions that
// run no code and change no policy. The handler narrows what helpdesk may
// do where a route does more than that.
func (h *Handler) operate(next http.HandlerFunc) http.Handler {
	return h.protect(next, access{operate: true})
}
func (h *Handler) operateSession(next http.HandlerFunc) http.Handler {
	return h.protect(next, access{operate: true, session: true})
}

// readFleet and writeFleet are for what concerns the whole fleet rather than
// particular devices - item definitions, groups, alerting, the audit log - and
// refuse a scoped admin.
func (h *Handler) readFleet(next http.HandlerFunc) http.Handler {
	return h.protect(next, access{fleet: true})
}
func (h *Handler) writeFleet(next http.HandlerFunc) http.Handler {
	return h.protect(next, access{admin: true, fleet: true})
}

// readSession and writeSession refuse API tokens, for what only a person at
// a console should do: reveal a recovery key, look at their own session. A
// scoped admin may, within their devices.
func (h *Handler) readSession(next http.HandlerFunc) http.Handler {
	return h.protect(next, access{session: true})
}
func (h *Handler) writeSession(next http.HandlerFunc) http.Handler {
	return h.protect(next, access{admin: true, session: true})
}

// readAdmin and writeAdmin manage admins and API tokens: a person, unscoped.
// A leaked token cannot make its own replacements to outlive revocation, and
// a scoped admin cannot widen their own scope or make an unscoped account.
func (h *Handler) readAdmin(next http.HandlerFunc) http.Handler {
	return h.protect(next, access{session: true, fleet: true})
}
func (h *Handler) writeAdmin(next http.HandlerFunc) http.Handler {
	return h.protect(next, access{admin: true, session: true, fleet: true})
}

// protect authenticates the caller - an API token in the Authorization
// header, else the session cookie - enforces CSRF on a session's unsafe
// methods, checks the role, and loads the caller's scope.
func (h *Handler) protect(next http.HandlerFunc, a access) http.Handler {
	return guarded{access: a, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A request that sends an Authorization header is judged on it alone,
		// never on a cookie that happens to ride along with it.
		if header := r.Header.Get("Authorization"); header != "" {
			h.withToken(w, r, header, next, a)
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
		if a.admin && admin.Role != store.RoleAdmin {
			writeError(w, http.StatusForbidden, "forbidden", "this needs the admin role")
			return
		}
		if a.operate && store.RoleRank(admin.Role) < store.RoleRank(store.RoleHelpdesk) {
			writeError(w, http.StatusForbidden, "forbidden", "this account may only read")
			return
		}
		h.withScope(w, r, next, a, authContext{Admin: admin, Session: session}, admin.ID)
	})}
}

// withToken authenticates an API token. It needs no CSRF check: the header
// is something a script sets on purpose, never something a browser attaches
// to a request another site made it send.
func (h *Handler) withToken(w http.ResponseWriter, r *http.Request, header string, next http.HandlerFunc, a access) {
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
	if a.session {
		writeError(w, http.StatusForbidden, "session_required", "this needs an admin signed in to the console; an API token cannot do it")
		return
	}
	if a.admin && tok.Role != store.RoleAdmin {
		writeError(w, http.StatusForbidden, "forbidden", "this needs a token with the admin role")
		return
	}
	if a.operate && store.RoleRank(tok.Role) < store.RoleRank(store.RoleHelpdesk) {
		writeError(w, http.StatusForbidden, "forbidden", "this token may only read")
		return
	}
	admin := store.Admin{ID: tok.ID, Email: "api-token:" + tok.Name, Role: tok.Role, AuthSource: authSourceAPIToken}
	// A token sees what its maker sees now, not what they saw when they made
	// it: narrowing an admin narrows every token they hold.
	h.withScope(w, r, next, a, authContext{Admin: admin, Token: &tok}, tok.CreatedByID)
}

// withScope loads the scope of the admin a request acts for and refuses a
// scoped caller a fleet route.
func (h *Handler) withScope(w http.ResponseWriter, r *http.Request, next http.HandlerFunc, a access, ac authContext, adminID uuid.UUID) {
	scope, err := h.Store.Q().AdminScope(r.Context(), store.DefaultTenantID, adminID)
	if err != nil {
		h.internal(w, "load admin scope", err)
		return
	}
	if a.fleet && scope.Limited() {
		writeError(w, http.StatusForbidden, "scoped", "this concerns the whole fleet, and this account is limited to some device groups")
		return
	}
	ac.Scope = scope
	next(w, r.WithContext(context.WithValue(r.Context(), authKey{}, ac)))
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
