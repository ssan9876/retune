package agentapi_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"

	"retune/internal/server/agentapi"
)

// testCA returns a throwaway certificate authority.
func testCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

// testLeaf issues a client certificate with commonName as its subject.
func testLeaf(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, commonName string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func encodePEM(cert *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}

func TestHeaderClientCert(t *testing.T) {
	caCert, caKey := testCA(t)
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	leaf := testLeaf(t, caCert, caKey, uuid.New().String())
	encoded := url.QueryEscape(encodePEM(leaf))

	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	get := agentapi.HeaderClientCert("X-Forwarded-Client-Cert", trusted, pool)

	newReq := func(remote, header string) *http.Request {
		r := httptest.NewRequest("POST", "/api/agent/v1/checkin", nil)
		r.RemoteAddr = remote
		if header != "" {
			r.Header.Set("X-Forwarded-Client-Cert", header)
		}
		return r
	}

	t.Run("trusted peer with a valid certificate", func(t *testing.T) {
		got, err := get(newReq("10.1.2.3:4567", encoded))
		if err != nil {
			t.Fatal(err)
		}
		if got == nil || got.SerialNumber.Cmp(leaf.SerialNumber) != 0 {
			t.Fatal("wrong certificate returned")
		}
	})

	t.Run("accepts unescaped PEM", func(t *testing.T) {
		if _, err := get(newReq("10.1.2.3:4567", encodePEM(leaf))); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("untrusted peer sending the header is rejected", func(t *testing.T) {
		_, err := get(newReq("203.0.113.9:4567", encoded))
		var ce agentapi.CertError
		if !errors.As(err, &ce) || ce.Status != http.StatusForbidden {
			t.Fatalf("want 403 CertError, got %v", err)
		}
	})

	t.Run("untrusted peer without the header presents no certificate", func(t *testing.T) {
		got, err := get(newReq("203.0.113.9:4567", ""))
		if err != nil || got != nil {
			t.Fatalf("want (nil, nil), got (%v, %v)", got, err)
		}
	})

	t.Run("trusted peer without the header presents no certificate", func(t *testing.T) {
		got, err := get(newReq("10.1.2.3:4567", ""))
		if err != nil || got != nil {
			t.Fatalf("want (nil, nil), got (%v, %v)", got, err)
		}
	})

	t.Run("malformed header", func(t *testing.T) {
		_, err := get(newReq("10.1.2.3:4567", "not-a-certificate"))
		var ce agentapi.CertError
		if !errors.As(err, &ce) || ce.Status != http.StatusUnauthorized {
			t.Fatalf("want 401 CertError, got %v", err)
		}
	})

	t.Run("certificate from another CA", func(t *testing.T) {
		otherCA, otherKey := testCA(t)
		foreign := testLeaf(t, otherCA, otherKey, uuid.New().String())
		_, err := get(newReq("10.1.2.3:4567", url.QueryEscape(encodePEM(foreign))))
		var ce agentapi.CertError
		if !errors.As(err, &ce) || ce.Status != http.StatusUnauthorized {
			t.Fatalf("want 401 CertError, got %v", err)
		}
	})
}

func TestTLSClientCertWithoutHandshake(t *testing.T) {
	r := httptest.NewRequest("POST", "/api/agent/v1/checkin", nil)
	got, err := agentapi.TLSClientCert(r)
	if err != nil || got != nil {
		t.Fatalf("want (nil, nil), got (%v, %v)", got, err)
	}
}
