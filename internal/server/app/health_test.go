package app_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

// probe fetches a URL with no session and no client certificate, which is
// what a load balancer's check is.
func probe(t *testing.T, client *http.Client, url string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	return res.StatusCode, strings.TrimSpace(string(body))
}

func TestHealthProbesNeedNoSession(t *testing.T) {
	a, srv := newTestApp(t)
	client := httpClient(a, nil)

	for _, path := range []string{"/healthz", "/readyz"} {
		status, body := probe(t, client, srv.URL+path)
		if status != http.StatusOK || body != "ok" {
			t.Errorf("GET %s = %d %q, want 200 \"ok\"", path, status, body)
		}
	}
}

func TestReadyzReportsAnUnreachableDatabase(t *testing.T) {
	a, srv := newTestApp(t)
	client := httpClient(a, nil)

	// Closing the pool is the nearest thing to the database going away that a
	// test can arrange; the app's own cleanup closes it again, which the pool
	// tolerates.
	a.Close()

	status, body := probe(t, client, srv.URL+"/readyz")
	if status != http.StatusServiceUnavailable {
		t.Errorf("GET /readyz with no database = %d, want 503", status)
	}
	// The body says what is wrong without saying where the database is or how
	// this server authenticates to it.
	if body != "database unavailable" {
		t.Errorf("body = %q, want %q", body, "database unavailable")
	}

	// Liveness is deliberately unaffected: the process is still the process.
	if status, body := probe(t, client, srv.URL+"/healthz"); status != http.StatusOK || body != "ok" {
		t.Errorf("GET /healthz with no database = %d %q, want 200 \"ok\"", status, body)
	}
}
