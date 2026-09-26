package adminapi

import (
	"errors"
	"net/http"
	"net/url"

	"retune/internal/server/auth"
)

// oidcCookiePath scopes the in-progress sign-in cookie to the two endpoints
// that use it, so it rides on no other request.
const oidcCookiePath = "/api/admin/v1/oidc/"

// oidcStart sends the browser to the identity provider, carrying a sealed
// cookie that proves on the way back which sign-in it started.
func (h *Handler) oidcStart(w http.ResponseWriter, r *http.Request) {
	if h.SSO == nil {
		http.NotFound(w, r)
		return
	}
	redirect, cookie, err := h.SSO.Start(r.Context())
	if err != nil {
		h.ssoFailed(w, r, err)
		return
	}
	// Lax, not Strict: the provider's redirect back is a cross-site
	// navigation, and a Strict cookie would not come with it.
	http.SetCookie(w, &http.Cookie{
		Name: auth.LoginCookie, Value: cookie, Path: oidcCookiePath, MaxAge: int(auth.LoginTTL.Seconds()),
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, redirect, http.StatusFound)
}

// oidcCallback finishes a sign-in and hands the browser the same session
// cookie a password sign-in would. Every failure lands on the sign-in page
// with a code and nothing else in the URL; the detail goes to the log.
func (h *Handler) oidcCallback(w http.ResponseWriter, r *http.Request) {
	if h.SSO == nil {
		http.NotFound(w, r)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: auth.LoginCookie, Value: "", Path: oidcCookiePath, MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		h.log().Warn("the identity provider refused the sign-in", "error", e, "description", q.Get("error_description"))
		redirectToLogin(w, r, auth.SSOProvider)
		return
	}
	cookie := ""
	if c, err := r.Cookie(auth.LoginCookie); err == nil {
		cookie = c.Value
	}
	admin, err := h.SSO.Finish(r.Context(), cookie, q.Get("state"), q.Get("code"))
	if err != nil {
		h.ssoFailed(w, r, err)
		return
	}
	info, err := h.Auth.CreateSession(r.Context(), admin.ID, r.UserAgent(), h.clientIP(r))
	if err != nil {
		h.log().Error("create session after SSO", "error", err)
		redirectToLogin(w, r, auth.SSOUnavailable)
		return
	}
	h.setSessionCookie(w, info)
	http.Redirect(w, r, "/", http.StatusFound)
}

func (h *Handler) ssoFailed(w http.ResponseWriter, r *http.Request, err error) {
	var sso *auth.SSOError
	if !errors.As(err, &sso) {
		h.log().Error("SSO sign-in failed", "error", err)
		redirectToLogin(w, r, auth.SSOUnavailable)
		return
	}
	h.log().Warn("SSO sign-in refused", "code", sso.Code, "error", sso.Err)
	redirectToLogin(w, r, sso.Code)
}

// redirectToLogin sends the browser to the console's root, which shows the
// sign-in page to anyone not signed in. Not to a /login path: the console has
// no such route, and a later password sign-in would leave the browser on it.
func redirectToLogin(w http.ResponseWriter, r *http.Request, code string) {
	http.Redirect(w, r, "/?sso_error="+url.QueryEscape(code), http.StatusFound)
}
