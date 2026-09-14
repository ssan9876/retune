package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"retune/internal/pki"
)

// clientFor builds a pinned Client against srv. New requires an https URL, so
// srv must be a TLS test server (httptest.NewTLSServer), matching the
// existing newServer helper in client_test.go.
func clientFor(t *testing.T, srv *httptest.Server) *Client {
	t.Helper()
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, pki.Fingerprint(srv.Certificate().Raw), nil)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// The download is verified against the hash the definition promised, so a
// corrupted or tampered payload is refused rather than executed.
func TestDownloadAgentBinaryVerifiesTheHash(t *testing.T) {
	const payload = "a pretend agent binary"
	sum := sha256.Sum256([]byte(payload))
	good := hex.EncodeToString(sum[:])

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(payload))
	}))
	c := clientFor(t, srv)

	var buf bytes.Buffer
	if err := c.DownloadAgentBinary(context.Background(), "id", good, &buf); err != nil {
		t.Fatalf("a matching hash should be accepted: %v", err)
	}
	if buf.String() != payload {
		t.Errorf("downloaded %q", buf.String())
	}

	buf.Reset()
	err := c.DownloadAgentBinary(context.Background(), "id", strings.Repeat("0", 64), &buf)
	if err == nil {
		t.Fatal("a mismatched hash must be refused")
	}
	if !strings.Contains(err.Error(), "sha256") {
		t.Errorf("the error should name what failed, got %v", err)
	}
}

// A large download must not be killed by the JSON client's short timeout.
func TestDownloadAgentBinaryOutlivesTheJSONTimeout(t *testing.T) {
	// Served slowly enough that a 60s whole-request budget would be tight, but
	// fast enough for a test: the point is that the download does not share
	// the JSON client's Timeout field at all.
	c := clientFor(t, httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("x"))
	})))
	if c.DownloadTimeout() <= 60*time.Second {
		t.Errorf("the download budget is %v; it must be larger than the JSON client's 60s",
			c.DownloadTimeout())
	}
}
