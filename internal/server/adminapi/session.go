package adminapi

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
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
	// AuthSource is "local" or "oidc": whether the account signs in with a
	// password here or through the identity provider.
	AuthSource string `json:"auth_source"`
	// Scope is the device groups the admin is limited to, or null for the
	// whole fleet. An empty list is limited to nothing.
	Scope []string `json:"scope"`
}

func newAdminJSON(a store.Admin) adminJSON {
	source := a.AuthSource
	if source == "" {
		source = store.AuthLocal
	}
	return adminJSON{
		ID: a.ID.String(), Email: a.Email, Role: a.Role,
		TOTPEnabled: a.TOTPSecret != "", Disabled: a.DisabledAt != nil,
		CreatedAt: a.CreatedAt, LastLoginAt: a.LastLoginAt, AuthSource: source,
	}
}

// withScope fills in an admin's scope for the API.
func (j adminJSON) withScope(scope store.DeviceScope) adminJSON {
	if scope.Limited() {
		j.Scope = make([]string, 0, len(scope))
		for _, g := range scope {
			j.Scope = append(j.Scope, g.String())
		}
	}
	return j
}

type sessionResponse struct {
	Admin     adminJSON `json:"admin"`
	CSRFToken string    `json:"csrf_token"`
	ExpiresAt time.Time `json:"expires_at"`
	// SigningRequired says scripts and wipes need an operations signature.
	SigningRequired bool `json:"signing_required"`
	// AgentDownloadURL is where the agent installers can be downloaded.
	AgentDownloadURL string `json:"agent_download_url,omitempty"`
}

type ssoSetup struct {
	Enabled     bool   `json:"enabled"`
	DisplayName string `json:"display_name,omitempty"`
}

type setupResponse struct {
	NeedsSetup bool     `json:"needs_setup"`
	SSO        ssoSetup `json:"sso"`
	LocalLogin bool     `json:"local_login"`
}

// setup tells the sign-in page what to offer: whether the first admin still
// has to be created, whether there is an SSO button, and whether there is a
// password form.
func (h *Handler) setup(w http.ResponseWriter, r *http.Request) {
	has, err := h.Auth.HasAdmins(r.Context())
	if err != nil {
		h.internal(w, "count admins", err)
		return
	}
	resp := setupResponse{NeedsSetup: !has, LocalLogin: !h.Auth.LocalLoginDisabled}
	if h.SSO != nil {
		resp.SSO = ssoSetup{Enabled: true, DisplayName: h.SSOName}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if !decode(w, r, &req) {
		return
	}
	admin, err := h.Auth.AuthenticateFrom(r.Context(), h.clientIP(r), req.Email, req.Password, req.TOTPCode)
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
	case errors.Is(err, auth.ErrLocalLoginDisabled):
		writeError(w, http.StatusForbidden, "local_login_disabled", "password sign-in is turned off; sign in with SSO")
		return
	default:
		h.internal(w, "authenticate", err)
		return
	}

	info, err := h.Auth.CreateSession(r.Context(), admin.ID, r.UserAgent(), h.clientIP(r))
	if err != nil {
		h.internal(w, "create session", err)
		return
	}
	h.setSessionCookie(w, info)
	writeJSON(w, http.StatusOK, sessionResponse{
		Admin: newAdminJSON(admin), CSRFToken: info.CSRFToken, ExpiresAt: info.ExpiresAt,
		SigningRequired: h.SigningRequired, AgentDownloadURL: h.AgentDownloadURL,
	})
}

// setSessionCookie is the one place the session cookie is issued, for a
// password sign-in and an SSO one alike.
func (h *Handler) setSessionCookie(w http.ResponseWriter, info auth.SessionInfo) {
	http.SetCookie(w, &http.Cookie{
		Name: SessionCookie, Value: info.Token, Path: "/",
		Expires: info.ExpiresAt, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
}

func (h *Handler) currentSession(w http.ResponseWriter, r *http.Request) {
	c := caller(r)
	writeJSON(w, http.StatusOK, sessionResponse{
		Admin: newAdminJSON(c.Admin).withScope(c.Scope), CSRFToken: c.Session.CSRFToken, ExpiresAt: c.Session.ExpiresAt,
		SigningRequired: h.SigningRequired, AgentDownloadURL: h.AgentDownloadURL,
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

// clientIP is the address a request came from. X-Forwarded-For is believed
// only from a trusted proxy, and then read from the right, past any further
// trusted proxies: whatever is left of the first untrusted address was
// written by the client, and could say anything.
func (h *Handler) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if !h.trustedProxy(host) {
		return host
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		addr, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			break
		}
		if !h.trustedProxy(addr.String()) {
			return addr.Unmap().String()
		}
	}
	return host
}

func (h *Handler) trustedProxy(host string) bool {
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	for _, p := range h.TrustedProxies {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
