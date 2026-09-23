package console_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"retune/internal/server/console"
)

func get(t *testing.T, path string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	console.Handler().ServeHTTP(rec, req)
	return rec.Result()
}

func TestServesTheConsole(t *testing.T) {
	res := get(t, "/")
	defer res.Body.Close()
	if console.Built() && res.StatusCode != http.StatusOK {
		t.Fatalf("GET / = %d", res.StatusCode)
	}
	if !console.Built() && res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("without a build, GET / = %d, want 503", res.StatusCode)
	}
	if got := res.Header.Get("Content-Security-Policy"); !strings.Contains(got, "default-src 'self'") {
		t.Fatalf("CSP = %q", got)
	}
	if got := res.Header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q", got)
	}
	if got := res.Header.Get("Strict-Transport-Security"); !strings.HasPrefix(got, "max-age=") {
		t.Fatalf("Strict-Transport-Security = %q", got)
	}
}

func TestClientRoutesFallBackToIndex(t *testing.T) {
	if !console.Built() {
		t.Skip("console has not been built")
	}
	res := get(t, "/devices/01a0-1")
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET /devices/01a0-1 = %d, want the console's index", res.StatusCode)
	}
	if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("Content-Type = %q", ct)
	}
}

func TestUnknownAssetIsNotFound(t *testing.T) {
	if !console.Built() {
		t.Skip("console has not been built")
	}
	res := get(t, "/assets/does-not-exist.js")
	defer res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("missing asset = %d, want 404", res.StatusCode)
	}
}

func TestAssetsAreCached(t *testing.T) {
	if !console.Built() {
		t.Skip("console has not been built")
	}
	res := get(t, "/")
	defer res.Body.Close()
	if got := res.Header.Get("Cache-Control"); got != "no-cache" {
		t.Fatalf("index Cache-Control = %q, want no-cache", got)
	}
}
