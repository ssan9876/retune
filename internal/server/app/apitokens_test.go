package app_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"retune/internal/server/app"
	"retune/internal/server/store"
)

// bearer calls the admin API the way a script does: a token, no cookies, no
// CSRF header.
func bearer(t *testing.T, a *app.App, srv *httptest.Server, token, method, path string, body any) (int, []byte) {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, srv.URL+"/api/admin/v1"+path, r)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: a.CA.Pool()}}}
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	out, _ := io.ReadAll(res.Body)
	return res.StatusCode, out
}

type createdToken struct {
	Token    string `json:"token"`
	APIToken struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Role string `json:"role"`
	} `json:"api_token"`
}

func makeToken(t *testing.T, admin *adminClient, name, role string) createdToken {
	t.Helper()
	status, body := admin.do(http.MethodPost, "/api-tokens", map[string]any{"name": name, "role": role})
	if status != http.StatusCreated {
		t.Fatalf("create token: %d %s", status, body)
	}
	tok := decodeJSON[createdToken](t, body)
	if !strings.HasPrefix(tok.Token, "rtk_") {
		t.Fatalf("token = %q", tok.Token)
	}
	return tok
}

func TestAPITokensCallTheAPIWithoutASession(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)
	writer := makeToken(t, admin, "ticketing", store.RoleAdmin)
	reader := makeToken(t, admin, "dashboards", store.RoleReadOnly)

	if status, body := bearer(t, a, srv, reader.Token, http.MethodGet, "/devices", nil); status != http.StatusOK {
		t.Fatalf("a read-only token should read: %d %s", status, body)
	}
	// Writes need no CSRF header with a token: nothing sends it by accident.
	status, body := bearer(t, a, srv, writer.Token, http.MethodPost, "/groups",
		map[string]any{"name": "From a script", "kind": "static"})
	if status != http.StatusCreated {
		t.Fatalf("an admin token should write: %d %s", status, body)
	}
	if status, _ := bearer(t, a, srv, reader.Token, http.MethodPost, "/groups",
		map[string]any{"name": "Not allowed", "kind": "static"}); status != http.StatusForbidden {
		t.Errorf("a read-only token must not write, got %d", status)
	}

	// The audit log says the token did it.
	_, body = admin.do(http.MethodGet, "/audit", nil)
	if !strings.Contains(string(body), `"actor":"api-token:ticketing"`) {
		t.Errorf("the audit log should name the token: %s", body)
	}
	// The listing never includes a secret.
	_, body = admin.do(http.MethodGet, "/api-tokens", nil)
	if strings.Contains(string(body), writer.Token) || strings.Contains(string(body), "rtk_") {
		t.Errorf("a token must never be shown again: %s", body)
	}
}

// What only a person at the console should do stays out of a token's reach,
// so a leaked token cannot mint its own replacements or accounts, or read out
// recovery keys.
func TestAPITokensCannotDoSessionOnlyThings(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)
	tok := makeToken(t, admin, "automation", store.RoleAdmin)

	for _, call := range []struct{ method, path string }{
		{http.MethodGet, "/api-tokens"},
		{http.MethodPost, "/api-tokens"},
		{http.MethodPost, "/admins"},
		{http.MethodGet, "/session"},
		{http.MethodPost, "/bitlocker-keys/00000000-0000-0000-0000-000000000000/reveal"},
	} {
		status, body := bearer(t, a, srv, tok.Token, call.method, call.path, map[string]any{})
		if status != http.StatusForbidden || !strings.Contains(string(body), "session_required") {
			t.Errorf("%s %s with a token: %d %s", call.method, call.path, status, body)
		}
	}
}

func TestAPITokensStopWorkingWhenRevokedOrTheirMakerIsDisabled(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)
	revoked := makeToken(t, admin, "old script", store.RoleReadOnly)
	if status, body := admin.do(http.MethodPost, "/api-tokens/"+revoked.APIToken.ID+"/revoke", nil); status != http.StatusNoContent {
		t.Fatalf("revoke: %d %s", status, body)
	}
	if status, _ := bearer(t, a, srv, revoked.Token, http.MethodGet, "/devices", nil); status != http.StatusUnauthorized {
		t.Errorf("a revoked token should be refused, got %d", status)
	}
	// A revoked token gives its name back.
	makeToken(t, admin, "old script", store.RoleReadOnly)
	if status, _ := admin.do(http.MethodPost, "/api-tokens", map[string]any{"name": "old script", "role": "read_only"}); status != http.StatusConflict {
		t.Errorf("two live tokens with one name should conflict, got %d", status)
	}

	// A second admin makes a token, then is disabled.
	seedAdmin(t, a, "leaver@example.com", testPassword, store.RoleAdmin)
	leaver := newAdminClient(t, a, srv)
	if status, body := leaver.login("leaver@example.com", testPassword, ""); status != http.StatusOK {
		t.Fatalf("login: %d %s", status, body)
	}
	theirs := makeToken(t, leaver, "leaver's cron job", store.RoleAdmin)
	if status, _ := bearer(t, a, srv, theirs.Token, http.MethodGet, "/devices", nil); status != http.StatusOK {
		t.Fatal("the token should work while its maker is enabled")
	}
	_, body := admin.do(http.MethodGet, "/admins", nil)
	var admins struct {
		Items []struct {
			ID    string `json:"id"`
			Email string `json:"email"`
		} `json:"items"`
	}
	_ = json.Unmarshal(body, &admins)
	for _, x := range admins.Items {
		if x.Email == "leaver@example.com" {
			if status, body := admin.do(http.MethodPost, "/admins/"+x.ID+"/disabled", map[string]bool{"disabled": true}); status != http.StatusNoContent {
				t.Fatalf("disable: %d %s", status, body)
			}
		}
	}
	if status, _ := bearer(t, a, srv, theirs.Token, http.MethodGet, "/devices", nil); status != http.StatusUnauthorized {
		t.Errorf("a disabled admin's tokens should stop working, got %d", status)
	}

	for _, bad := range []string{"rtk_not-a-real-token", "not-even-the-prefix", ""} {
		if status, _ := bearer(t, a, srv, bad, http.MethodGet, "/devices", nil); status != http.StatusUnauthorized {
			t.Errorf("token %q: want 401, got %d", bad, status)
		}
	}
}

func TestAPITokenLimits(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)
	for _, req := range []map[string]any{
		{"name": "", "role": "admin"},
		{"name": "x", "role": "owner"},
		{"name": "x", "role": "admin", "expires_in_days": 366},
		{"name": "x", "role": "admin", "expires_in_days": -1},
	} {
		if status, body := admin.do(http.MethodPost, "/api-tokens", req); status != http.StatusBadRequest {
			t.Errorf("%v: want 400, got %d %s", req, status, body)
		}
	}
	viewer := signedIn(t, a, srv, store.RoleReadOnly)
	if status, _ := viewer.do(http.MethodPost, "/api-tokens", map[string]any{"name": "mine", "role": "read_only"}); status != http.StatusForbidden {
		t.Errorf("a read-only admin must not make tokens, got %d", status)
	}
}
