package app_test

import (
	"bytes"
	"context"
	"net/http"
	"testing"

	"retune/internal/server/store"
)

func TestSetupAndLogin(t *testing.T) {
	a, srv := newTestApp(t)
	c := newAdminClient(t, a, srv)

	status, body := c.do(http.MethodGet, "/setup", nil)
	if status != http.StatusOK || !bytes.Contains(body, []byte(`"needs_setup":true`)) {
		t.Fatalf("setup before any admin: %d %s", status, body)
	}
	seedAdmin(t, a, "ops@example.com", testPassword, store.RoleAdmin)
	if _, body = c.do(http.MethodGet, "/setup", nil); !bytes.Contains(body, []byte(`"needs_setup":false`)) {
		t.Fatalf("setup after seeding: %s", body)
	}

	if status, body = c.do(http.MethodGet, "/session", nil); status != http.StatusUnauthorized {
		t.Fatalf("session without login: %d %s", status, body)
	}
	if status, body = c.login("ops@example.com", "wrong password", ""); status != http.StatusUnauthorized ||
		!bytes.Contains(body, []byte("invalid_credentials")) {
		t.Fatalf("bad password: %d %s", status, body)
	}
	status, body = c.login("ops@example.com", testPassword, "")
	if status != http.StatusOK || !bytes.Contains(body, []byte(`"email":"ops@example.com"`)) {
		t.Fatalf("login: %d %s", status, body)
	}
	if c.csrf == "" {
		t.Fatal("login must return a CSRF token")
	}
	cookie := c.sessionCookie()
	if cookie == nil || !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("session cookie = %+v", cookie)
	}

	if status, body = c.do(http.MethodGet, "/session", nil); status != http.StatusOK ||
		!bytes.Contains(body, []byte(`"role":"admin"`)) {
		t.Fatalf("session after login: %d %s", status, body)
	}

	// CSRF is required for unsafe methods.
	saved := c.csrf
	c.csrf = ""
	if status, body = c.do(http.MethodDelete, "/session", nil); status != http.StatusForbidden ||
		!bytes.Contains(body, []byte("csrf_invalid")) {
		t.Fatalf("logout without CSRF: %d %s", status, body)
	}
	c.csrf = "wrong-token"
	if status, _ = c.do(http.MethodDelete, "/session", nil); status != http.StatusForbidden {
		t.Fatalf("logout with a wrong CSRF token: %d", status)
	}
	c.csrf = saved

	if status, body = c.do(http.MethodDelete, "/session", nil); status != http.StatusNoContent {
		t.Fatalf("logout: %d %s", status, body)
	}
	if status, _ = c.do(http.MethodGet, "/session", nil); status != http.StatusUnauthorized {
		t.Fatalf("session after logout: %d", status)
	}
}

func TestLockoutAndDisabledAccount(t *testing.T) {
	ctx := context.Background()
	a, srv := newTestApp(t)
	admin := seedAdmin(t, a, "ops@example.com", testPassword, store.RoleAdmin)
	seedAdmin(t, a, "ops2@example.com", testPassword, store.RoleAdmin)
	c := newAdminClient(t, a, srv)

	for range 10 {
		if status, _ := c.login("ops@example.com", "wrong password", ""); status != http.StatusUnauthorized {
			t.Fatal("expected 401 while failing")
		}
	}
	status, body := c.login("ops@example.com", testPassword, "")
	if status != http.StatusTooManyRequests || !bytes.Contains(body, []byte("too_many_attempts")) {
		t.Fatalf("lockout: %d %s", status, body)
	}

	other := newAdminClient(t, a, srv)
	if status, _ := other.login("ops2@example.com", testPassword, ""); status != http.StatusOK {
		t.Fatal("a different account must not be locked out")
	}

	// Disable the second account, which is not rate limited, and check the
	// error it gets. (ops@example.com is locked out, so it would see 429 first.)
	second, err := a.Store.Q().GetAdminByEmail(ctx, store.DefaultTenantID, "ops2@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Auth.SetDisabled(ctx, second.ID, true, "test"); err != nil {
		t.Fatal(err)
	}
	disabled := newAdminClient(t, a, srv)
	if status, body := disabled.login("ops2@example.com", testPassword, ""); status != http.StatusForbidden ||
		!bytes.Contains(body, []byte("account_disabled")) {
		t.Fatalf("disabled login: %d %s", status, body)
	}
	// Its existing session stops working as well.
	if status, _ := other.do(http.MethodGet, "/session", nil); status != http.StatusUnauthorized {
		t.Fatal("disabling an account must end its sessions")
	}
	_ = admin
}

func TestReadOnlyRole(t *testing.T) {
	a, srv := newTestApp(t)
	c := signedIn(t, a, srv, store.RoleReadOnly)
	if status, _ := c.do(http.MethodGet, "/session", nil); status != http.StatusOK {
		t.Fatal("a read-only admin must be able to read")
	}
	status, body := c.do(http.MethodPost, "/tokens", map[string]any{"label": "nope"})
	if status != http.StatusForbidden || !bytes.Contains(body, []byte("forbidden")) {
		t.Fatalf("read-only write: %d %s", status, body)
	}
}

func TestDeletedSessionCookieIsRejected(t *testing.T) {
	a, srv := newTestApp(t)
	seedAdmin(t, a, "ops@example.com", testPassword, store.RoleAdmin)
	c := newAdminClient(t, a, srv)
	if status, _ := c.login("ops@example.com", testPassword, ""); status != http.StatusOK {
		t.Fatal("login failed")
	}
	if err := a.Auth.DeleteSession(context.Background(), c.storedToken(srv)); err != nil {
		t.Fatal(err)
	}
	if status, body := c.do(http.MethodGet, "/session", nil); status != http.StatusUnauthorized ||
		!bytes.Contains(body, []byte("unauthenticated")) {
		t.Fatalf("deleted session: %d %s", status, body)
	}
}
