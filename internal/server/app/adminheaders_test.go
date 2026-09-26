package app_test

import (
	"net/http"
	"testing"

	"retune/internal/server/store"
)

// Admin API responses can carry recovery keys and local admin passwords, so
// none may be cached, and all are served as what they claim to be.
func TestAdminAPIResponsesAreNotCached(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)

	for _, path := range []string{"/devices", "/no-such-route"} {
		_, h, _ := admin.doWithHeaders(http.MethodGet, path, nil)
		if got := h.Get("Cache-Control"); got != "no-store" {
			t.Errorf("%s: Cache-Control = %q, want no-store", path, got)
		}
		if got := h.Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("%s: X-Content-Type-Options = %q, want nosniff", path, got)
		}
		if h.Get("Strict-Transport-Security") == "" {
			t.Errorf("%s: no Strict-Transport-Security", path)
		}
	}
}
