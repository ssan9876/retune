package app_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"retune/internal/config"
	"retune/internal/server/app"
	"retune/internal/server/auth"
	"retune/internal/server/auth/oidctest"
)

// newSSOApp is a test app with single sign-on pointed at a fake provider.
func newSSOApp(t *testing.T, adjust func(*config.OIDCConfig)) (*app.App, *httptest.Server, *oidctest.Provider) {
	t.Helper()
	idp := oidctest.New(t, "retune-console")
	a, srv := newTestAppWith(t, func(c *config.Server) {
		c.OIDC = config.OIDCConfig{
			Issuer: idp.Issuer(), ClientID: "retune-console", ClientSecret: "shh", GroupsClaim: "groups",
			AdminGroups: []string{"it-admins"}, ReadOnlyGroups: []string{"helpdesk"}, DisplayName: "Sign in with Contoso",
		}
		if adjust != nil {
			adjust(&c.OIDC)
		}
	})
	a.SSO.Client = idp.Client()
	return a, srv, idp
}

// browser does not follow redirects, so each hop of the sign-in can be seen.
func browser(t *testing.T, a *app.App) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{
		Jar:           jar,
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{RootCAs: a.CA.Pool()}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func get(t *testing.T, c *http.Client, u string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, u, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	return res
}

// ssoRoundTrip walks a browser through the whole sign-in: to the provider,
// back to the callback. It returns where the callback sent the browser.
func ssoRoundTrip(t *testing.T, c *http.Client, srv *httptest.Server, idp *oidctest.Provider, person oidctest.Person) *url.URL {
	t.Helper()
	start := get(t, c, srv.URL+"/api/admin/v1/oidc/start")
	if start.StatusCode != http.StatusFound || !strings.HasPrefix(start.Header.Get("Location"), idp.Issuer()+"/authorize") {
		t.Fatalf("start: %d to %q", start.StatusCode, start.Header.Get("Location"))
	}
	var loginCookie *http.Cookie
	for _, ck := range start.Cookies() {
		if ck.Name == auth.LoginCookie {
			loginCookie = ck
		}
	}
	if loginCookie == nil || !loginCookie.HttpOnly || !loginCookie.Secure || loginCookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("the sign-in cookie must be HttpOnly, Secure and Lax: %+v", loginCookie)
	}
	state, code := idp.Authorize(t, start.Header.Get("Location"), person, nil)
	back := get(t, c, srv.URL+"/api/admin/v1/oidc/callback?state="+url.QueryEscape(state)+"&code="+url.QueryEscape(code))
	if back.StatusCode != http.StatusFound {
		t.Fatalf("callback: %d", back.StatusCode)
	}
	loc, err := url.Parse(back.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return loc
}

func TestSSOSignInThroughTheBrowser(t *testing.T) {
	a, srv, idp := newSSOApp(t, nil)
	c := browser(t, a)

	res := get(t, c, srv.URL+"/api/admin/v1/setup")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("setup: %d", res.StatusCode)
	}

	loc := ssoRoundTrip(t, c, srv, idp, oidctest.Person{Subject: "u-1", Email: "ada@example.com", Groups: []string{"it-admins"}})
	if loc.Path != "/" {
		t.Fatalf("a successful sign-in should land on the console, went to %s", loc)
	}

	// The browser now holds a session, exactly as a password sign-in gives.
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/admin/v1/session", nil)
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	var session struct {
		Admin struct {
			Email      string `json:"email"`
			Role       string `json:"role"`
			AuthSource string `json:"auth_source"`
		} `json:"admin"`
	}
	if err := json.Unmarshal(body, &session); err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("session: %d %s", res.StatusCode, body)
	}
	if session.Admin.Email != "ada@example.com" || session.Admin.Role != "admin" || session.Admin.AuthSource != "oidc" {
		t.Fatalf("session = %+v", session.Admin)
	}
}

func TestSSOFailuresLandOnTheSignInPageWithACode(t *testing.T) {
	a, srv, idp := newSSOApp(t, nil)

	loc := ssoRoundTrip(t, browser(t, a), srv, idp, oidctest.Person{Subject: "u-2", Email: "eve@example.com", Groups: []string{"sales"}})
	if loc.Path != "/login" || loc.Query().Get("sso_error") != auth.SSOUnauthorized {
		t.Fatalf("unmapped: went to %s", loc)
	}

	// A callback with no sign-in in progress.
	res := get(t, browser(t, a), srv.URL+"/api/admin/v1/oidc/callback?state=x&code=y")
	if res.StatusCode != http.StatusFound || !strings.HasSuffix(res.Header.Get("Location"), "sso_error=state") {
		t.Fatalf("no cookie: %d to %q", res.StatusCode, res.Header.Get("Location"))
	}

	// The provider itself saying no. Its description goes to the log, not
	// into the URL.
	res = get(t, browser(t, a), srv.URL+"/api/admin/v1/oidc/callback?error=access_denied&error_description=secret+detail")
	if loc := res.Header.Get("Location"); !strings.HasSuffix(loc, "sso_error=provider_error") || strings.Contains(loc, "secret") {
		t.Fatalf("provider error: went to %q", loc)
	}
}

func TestSetupDescribesTheSignInOptions(t *testing.T) {
	a, srv, _ := newSSOApp(t, func(o *config.OIDCConfig) { o.DisableLocalLogin = true })
	c := newAdminClient(t, a, srv)
	status, body := c.do(http.MethodGet, "/setup", nil)
	if status != http.StatusOK ||
		!strings.Contains(string(body), `"sso":{"enabled":true,"display_name":"Sign in with Contoso"}`) ||
		!strings.Contains(string(body), `"local_login":false`) {
		t.Fatalf("setup: %d %s", status, body)
	}
	status, body = c.do(http.MethodPost, "/session", map[string]string{"email": "x@example.com", "password": "whatever"})
	if status != http.StatusForbidden || !strings.Contains(string(body), "local_login_disabled") {
		t.Fatalf("password sign-in with local login off: %d %s", status, body)
	}
}

func TestSSOEndpointsAreAbsentWithoutSSO(t *testing.T) {
	a, srv := newTestApp(t)
	c := newAdminClient(t, a, srv)
	if status, body := c.do(http.MethodGet, "/setup", nil); !strings.Contains(string(body), `"sso":{"enabled":false}`) ||
		!strings.Contains(string(body), `"local_login":true`) {
		t.Fatalf("setup without SSO: %d %s", status, body)
	}
	if res := get(t, browser(t, a), srv.URL+"/api/admin/v1/oidc/start"); res.StatusCode != http.StatusNotFound {
		t.Fatalf("start without SSO: %d", res.StatusCode)
	}
}
