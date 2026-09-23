package app_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"testing"

	"retune/internal/server/adminapi"
	"retune/internal/server/app"
	"retune/internal/server/auth"
	"retune/internal/server/store"
)

const testPassword = "correct horse battery"

// adminClient is a browser-like client: it keeps cookies and sends CSRF.
type adminClient struct {
	t    *testing.T
	http *http.Client
	base string
	csrf string
	// setCookies holds the cookies from the most recent response, which keep
	// the attributes a cookie jar throws away.
	setCookies []*http.Cookie
}

func newAdminClient(t *testing.T, a *app.App, srv *httptest.Server) *adminClient {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &adminClient{
		t: t, base: srv.URL + "/api/admin/v1",
		http: &http.Client{
			Jar:       jar,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: a.CA.Pool()}},
		},
	}
}

func (c *adminClient) do(method, path string, body any) (int, []byte) {
	c.t.Helper()
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			c.t.Fatal(err)
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, c.base+path, r)
	if err != nil {
		c.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.csrf != "" {
		req.Header.Set(adminapi.CSRFHeader, c.csrf)
	}
	res, err := c.http.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer res.Body.Close()
	c.setCookies = res.Cookies()
	out, _ := io.ReadAll(res.Body)
	return res.StatusCode, out
}

// doWithHeaders is do but also returns the response headers, for endpoints
// (like the CSV exports) whose contract lives partly in headers rather than
// the JSON body every other admin endpoint returns.
func (c *adminClient) doWithHeaders(method, path string, body any) (int, http.Header, []byte) {
	c.t.Helper()
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			c.t.Fatal(err)
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, c.base+path, r)
	if err != nil {
		c.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.csrf != "" {
		req.Header.Set(adminapi.CSRFHeader, c.csrf)
	}
	res, err := c.http.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer res.Body.Close()
	c.setCookies = res.Cookies()
	out, _ := io.ReadAll(res.Body)
	return res.StatusCode, res.Header, out
}

// doRaw sends a non-JSON body, for endpoints that take bytes rather than an
// object. It keeps do's cookie and CSRF handling.
func (c *adminClient) doRaw(method, path, contentType string, body io.Reader) (int, []byte) {
	c.t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, c.base+path, body)
	if err != nil {
		c.t.Fatal(err)
	}
	req.Header.Set("Content-Type", contentType)
	if c.csrf != "" {
		req.Header.Set(adminapi.CSRFHeader, c.csrf)
	}
	res, err := c.http.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer res.Body.Close()
	c.setCookies = res.Cookies()
	out, _ := io.ReadAll(res.Body)
	return res.StatusCode, out
}

// doRawWithHeaders is doRaw with extra request headers, for uploads that
// carry a signature beside the body.
func (c *adminClient) doRawWithHeaders(method, path, contentType string, headers map[string]string, body io.Reader) (int, []byte) {
	c.t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, c.base+path, body)
	if err != nil {
		c.t.Fatal(err)
	}
	req.Header.Set("Content-Type", contentType)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if c.csrf != "" {
		req.Header.Set(adminapi.CSRFHeader, c.csrf)
	}
	res, err := c.http.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer res.Body.Close()
	c.setCookies = res.Cookies()
	out, err := io.ReadAll(res.Body)
	if err != nil {
		c.t.Fatal(err)
	}
	return res.StatusCode, out
}

// login signs in and remembers the CSRF token.
func (c *adminClient) login(email, password, code string) (int, []byte) {
	c.t.Helper()
	status, body := c.do(http.MethodPost, "/session", map[string]string{
		"email": email, "password": password, "totp_code": code,
	})
	if status == http.StatusOK {
		var resp struct {
			CSRFToken string `json:"csrf_token"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			c.t.Fatal(err)
		}
		c.csrf = resp.CSRFToken
	}
	return status, body
}

// sessionCookie returns the session cookie as the server set it, with its
// attributes intact.
func (c *adminClient) sessionCookie() *http.Cookie {
	c.t.Helper()
	for _, ck := range c.setCookies {
		if ck.Name == adminapi.SessionCookie {
			return ck
		}
	}
	return nil
}

// storedToken returns the session token the cookie jar holds.
func (c *adminClient) storedToken(srv *httptest.Server) string {
	c.t.Helper()
	u, _ := url.Parse(srv.URL)
	for _, ck := range c.http.Jar.Cookies(u) {
		if ck.Name == adminapi.SessionCookie {
			return ck.Value
		}
	}
	return ""
}

// seedAdmin creates an account directly through the service.
func seedAdmin(t *testing.T, a *app.App, email, password, role string) store.Admin {
	t.Helper()
	admin, err := a.Auth.CreateAdmin(context.Background(), auth.CreateAdminOptions{
		Email: email, Password: password, Role: role, Actor: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	return admin
}

// signedIn seeds an account with the given role and returns a logged-in client.
func signedIn(t *testing.T, a *app.App, srv *httptest.Server, role string) *adminClient {
	t.Helper()
	email := "ops@example.com"
	switch role {
	case store.RoleReadOnly:
		email = "viewer@example.com"
	case store.RoleHelpdesk:
		email = "helpdesk@example.com"
	}
	seedAdmin(t, a, email, testPassword, role)
	c := newAdminClient(t, a, srv)
	if status, body := c.login(email, testPassword, ""); status != http.StatusOK {
		t.Fatalf("login: %d %s", status, body)
	}
	return c
}
