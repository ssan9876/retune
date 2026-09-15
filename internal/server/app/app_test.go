package app_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"retune/internal/config"
	"retune/internal/protocol"
	"retune/internal/release"
	"retune/internal/server/app"
	"retune/internal/server/enroll"
	"retune/internal/server/store"
	"retune/internal/server/store/storetest"
)

// testReleaseKey is the release key newTestApp configures the app's server
// with, so agentversions_test.go can sign uploads against it.
var testReleaseKey release.PrivateKey

func newTestApp(t *testing.T) (*app.App, *httptest.Server) {
	t.Helper()
	priv, err := release.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	testReleaseKey = priv
	cfg := config.Server{
		DatabaseURL: storetest.DatabaseURL(t), PublicURL: "https://127.0.0.1",
		TLSMode: "self-signed", DataDir: t.TempDir(),
		CheckinInterval: 5 * time.Minute, SessionTTL: 12 * time.Hour,
		AgentReleaseKeys: []release.PublicKey{priv.Public()},
	}
	a, err := app.New(context.Background(), cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	srv := httptest.NewUnstartedServer(a.Handler)
	srv.TLS = a.TLSConfig
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return a, srv
}

func httpClient(a *app.App, cert *tls.Certificate) *http.Client {
	cfg := &tls.Config{RootCAs: a.CA.Pool()}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
}

func post(t *testing.T, c *http.Client, url string, body any) (int, []byte) {
	t.Helper()
	b, _ := json.Marshal(body)
	res, err := c.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	out, _ := io.ReadAll(res.Body)
	return res.StatusCode, out
}

func TestAgentAPI(t *testing.T) {
	ctx := context.Background()
	a, srv := newTestApp(t)
	plain, _, err := a.Enroll.CreateToken(ctx, enroll.TokenOptions{CreatedBy: "test"})
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
	anon := httpClient(a, nil)

	status, body := post(t, anon, srv.URL+"/api/agent/v1/enroll", protocol.EnrollRequest{Token: "rt_bad", CSRPEM: csrPEM, Device: protocol.DeviceFacts{Hostname: "PC-1"}})
	if status != http.StatusForbidden || !bytes.Contains(body, []byte("enrollment_token_invalid")) {
		t.Fatalf("bad token: %d %s", status, body)
	}
	status, body = post(t, anon, srv.URL+"/api/agent/v1/enroll", protocol.EnrollRequest{Token: plain, CSRPEM: "junk", Device: protocol.DeviceFacts{Hostname: "PC-1"}})
	if status != http.StatusBadRequest {
		t.Fatalf("bad csr: %d %s", status, body)
	}

	status, body = post(t, anon, srv.URL+"/api/agent/v1/enroll", protocol.EnrollRequest{Token: plain, CSRPEM: csrPEM, Device: protocol.DeviceFacts{Hostname: "PC-1"}})
	if status != http.StatusOK {
		t.Fatalf("enroll: %d %s", status, body)
	}
	var enrolled protocol.EnrollResponse
	if err := json.Unmarshal(body, &enrolled); err != nil {
		t.Fatal(err)
	}

	status, _ = post(t, anon, srv.URL+"/api/agent/v1/checkin", protocol.CheckinRequest{})
	if status != http.StatusUnauthorized {
		t.Fatalf("checkin without cert: %d", status)
	}

	block, _ := pem.Decode([]byte(enrolled.CertPEM))
	mtls := httpClient(a, &tls.Certificate{Certificate: [][]byte{block.Bytes}, PrivateKey: key})
	status, body = post(t, mtls, srv.URL+"/api/agent/v1/checkin", protocol.CheckinRequest{AgentVersion: "0.1.0"})
	if status != http.StatusOK {
		t.Fatalf("checkin: %d %s", status, body)
	}
	var cr protocol.CheckinResponse
	if err := json.Unmarshal(body, &cr); err != nil || cr.IntervalSeconds != 300 {
		t.Fatalf("checkin response %s, err %v", body, err)
	}
	id := uuid.MustParse(enrolled.DeviceID)
	if d, _ := a.Store.Q().GetDevice(ctx, store.DefaultTenantID, id); d.LastSeenAt == nil || d.AgentVersion != "0.1.0" {
		t.Fatalf("device after checkin = %+v", d)
	}

	if err := a.Store.Q().SetDeviceStatus(ctx, store.DefaultTenantID, id, store.DeviceRetired); err != nil {
		t.Fatal(err)
	}
	status, body = post(t, mtls, srv.URL+"/api/agent/v1/checkin", protocol.CheckinRequest{})
	if status != http.StatusUnauthorized || !bytes.Contains(body, []byte("device_not_active")) {
		t.Fatalf("retired checkin: %d %s", status, body)
	}
}
