package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"retune/internal/pki"
	"retune/internal/protocol"
)

func newServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/agent/v1/checkin" {
			_ = json.NewEncoder(w).Encode(protocol.CheckinResponse{IntervalSeconds: 60})
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(protocol.Error{Code: "enrollment_token_invalid", Message: "nope"})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestPinnedClient(t *testing.T) {
	ctx := context.Background()
	srv := newServer(t)
	pin := pki.Fingerprint(srv.Certificate().Raw)

	for _, p := range []string{pin, strings.ToUpper(pin)} {
		c, err := New(srv.URL, p, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := c.Checkin(ctx, protocol.CheckinRequest{})
		if err != nil || resp.IntervalSeconds != 60 {
			t.Fatalf("pin %s: resp=%+v err=%v", p, resp, err)
		}
	}

	c, _ := New(srv.URL, "sha256:"+strings.Repeat("0", 64), nil)
	_, err := c.Checkin(ctx, protocol.CheckinRequest{})
	var he *HTTPError
	if err == nil || errors.As(err, &he) {
		t.Fatalf("wrong pin must fail at TLS, got %v", err)
	}

	c, _ = New(srv.URL, "", nil)
	if _, err := c.Checkin(ctx, protocol.CheckinRequest{}); err == nil {
		t.Fatal("unpinned client must not trust a self-signed server")
	}
}

func TestHTTPError(t *testing.T) {
	srv := newServer(t)
	c, _ := New(srv.URL, pki.Fingerprint(srv.Certificate().Raw), nil)
	_, err := c.Enroll(context.Background(), protocol.EnrollRequest{})
	var he *HTTPError
	if !errors.As(err, &he) || he.Status != 403 || he.Code != "enrollment_token_invalid" || he.Retryable() {
		t.Fatalf("err = %#v", err)
	}
	for status, want := range map[int]bool{500: true, 503: true, 429: true, 400: false, 401: false} {
		if got := (&HTTPError{Status: status}).Retryable(); got != want {
			t.Errorf("Retryable(%d) = %v", status, got)
		}
	}
}

func TestNewRejectsHTTP(t *testing.T) {
	if _, err := New("http://mdm.example.com", "", nil); err == nil {
		t.Fatal("http URLs must be rejected")
	}
}
