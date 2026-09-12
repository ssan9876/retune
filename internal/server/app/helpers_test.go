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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"retune/internal/protocol"
	"retune/internal/server/app"
	"retune/internal/server/enroll"
)

// newKeyAndCSR returns a device keypair and its CSR in PEM form.
func newKeyAndCSR(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	return key, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

// clientFor builds an mTLS client from a device key and its certificate.
func clientFor(t *testing.T, a *app.App, key *ecdsa.PrivateKey, certPEM string) *http.Client {
	t.Helper()
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		t.Fatal("certificate is not PEM")
	}
	return httpClient(a, &tls.Certificate{Certificate: [][]byte{block.Bytes}, PrivateKey: key})
}

// send performs a JSON request and returns the status and raw body.
func send(t *testing.T, c *http.Client, method, url string, body any) (int, []byte) {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, url, r)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	out, _ := io.ReadAll(res.Body)
	return res.StatusCode, out
}

// enrollDevice enrolls one device and returns its ID and mTLS client.
func enrollDevice(t *testing.T, a *app.App, srv *httptest.Server, hostname string) (uuid.UUID, *http.Client) {
	t.Helper()
	ctx := context.Background()
	plain, _, err := a.Enroll.CreateToken(ctx, enroll.TokenOptions{CreatedBy: "test"})
	if err != nil {
		t.Fatal(err)
	}
	key, csrPEM := newKeyAndCSR(t)
	status, body := send(t, httpClient(a, nil), http.MethodPost, srv.URL+"/api/agent/v1/enroll",
		protocol.EnrollRequest{Token: plain, CSRPEM: csrPEM, Device: protocol.DeviceFacts{Hostname: hostname}})
	if status != http.StatusOK {
		t.Fatalf("enroll: %d %s", status, body)
	}
	var resp protocol.EnrollResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatal(err)
	}
	return uuid.MustParse(resp.DeviceID), clientFor(t, a, key, resp.CertPEM)
}

func decodeJSON[T any](t *testing.T, body []byte) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	return v
}
