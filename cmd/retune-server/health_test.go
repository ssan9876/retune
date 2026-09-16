package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"retune/internal/config"
)

func TestHealthcheckURL(t *testing.T) {
	cases := []struct {
		name string
		cfg  config.Server
		want string
	}{
		{"port only", config.Server{AgentListen: ":8443", TLSMode: "self-signed"}, "https://127.0.0.1:8443/readyz"},
		{"all interfaces", config.Server{AgentListen: "0.0.0.0:8443", TLSMode: "self-signed"}, "https://127.0.0.1:8443/readyz"},
		{"a named interface is dialled as given", config.Server{AgentListen: "10.0.0.5:9000", TLSMode: "provided"}, "https://10.0.0.5:9000/readyz"},
		// Behind a proxy the server itself speaks plain HTTP, so the probe
		// must too, or every check fails on a handshake that was never there.
		{"behind a proxy", config.Server{AgentListen: ":8080", TLSMode: "behind-proxy"}, "http://127.0.0.1:8080/readyz"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := healthcheckURL(tc.cfg); got != tc.want {
				t.Errorf("healthcheckURL = %q, want %q", got, tc.want)
			}
		})
	}
}

// probeServer stands in for a running server so the command can be exercised
// without one; only the status it returns matters here.
func probeServer(t *testing.T, status int, body string) func(string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/readyz" {
			t.Errorf("probed %s, want /readyz", r.URL.Path)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return env(map[string]string{
		"DATABASE_URL":     "postgres://retune@127.0.0.1:5432/retune",
		"PUBLIC_URL":       "https://mdm.example.com",
		"AGENT_API_LISTEN": strings.TrimPrefix(srv.URL, "http://"),
		"TLS_MODE":         "behind-proxy",
		"TRUSTED_PROXIES":  "127.0.0.1",
	})
}

func TestHealthcheckCmd(t *testing.T) {
	var out bytes.Buffer
	if err := healthcheckCmd(context.Background(), probeServer(t, http.StatusOK, "ok\n"), &out); err != nil {
		t.Fatalf("healthcheck on a ready server: %v", err)
	}
	if got := strings.TrimSpace(out.String()); got != "ready" {
		t.Errorf("output = %q, want %q", got, "ready")
	}
}

func TestHealthcheckCmdFailsWhenNotReady(t *testing.T) {
	var out bytes.Buffer
	err := healthcheckCmd(context.Background(),
		probeServer(t, http.StatusServiceUnavailable, "database unavailable\n"), &out)
	if err == nil {
		t.Fatal("healthcheck on an unready server succeeded, want an error")
	}
	// The exit status is what the container runtime acts on, but the message
	// is what an operator reads out of `docker inspect`, so it carries the
	// server's own words rather than just the status code.
	if !strings.Contains(err.Error(), "database unavailable") {
		t.Errorf("error = %v, want it to quote the server", err)
	}
}
