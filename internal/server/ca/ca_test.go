package ca

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var now = time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)

func newCA(t *testing.T) *CA {
	t.Helper()
	c, err := LoadOrCreate(context.Background(), FileKeyStore{Dir: t.TempDir()}, now)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func csrPEM(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func parseCert(t *testing.T, p []byte) *x509.Certificate {
	t.Helper()
	b, _ := pem.Decode(p)
	if b == nil {
		t.Fatal("no PEM block")
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestLoadOrCreatePersists(t *testing.T) {
	ks := FileKeyStore{Dir: t.TempDir()}
	a1, err := LoadOrCreate(context.Background(), ks, now)
	if err != nil {
		t.Fatal(err)
	}
	a2, err := LoadOrCreate(context.Background(), ks, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !a1.Cert().Equal(a2.Cert()) {
		t.Fatal("second LoadOrCreate must load the same CA")
	}
	if !a1.Cert().IsCA {
		t.Fatal("CA cert must have IsCA")
	}
	if !parseCert(t, a1.CertPEM()).Equal(a1.Cert()) {
		t.Fatal("CertPEM must encode Cert")
	}
}

func TestSignClientCSR(t *testing.T) {
	a := newCA(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	issued, err := a.SignClientCSR(csrPEM(t, key), "dev-1", now, 90*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert := parseCert(t, issued.PEM)
	if cert.Subject.CommonName != "dev-1" || cert.SerialNumber.Text(16) != issued.Serial || !cert.NotAfter.Equal(issued.NotAfter) {
		t.Fatalf("cert CN=%s serial=%s notAfter=%s; issued=%+v", cert.Subject.CommonName, cert.SerialNumber.Text(16), cert.NotAfter, issued)
	}
	if !issued.NotAfter.Equal(now.Add(90 * 24 * time.Hour)) {
		t.Fatalf("NotAfter = %s", issued.NotAfter)
	}
	opts := x509.VerifyOptions{Roots: a.Pool(), CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	if _, err := cert.Verify(opts); err != nil {
		t.Fatalf("client cert must verify for ClientAuth: %v", err)
	}
	opts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	if _, err := cert.Verify(opts); err == nil {
		t.Fatal("client cert must not verify for ServerAuth")
	}
}

func TestSignClientCSRRejects(t *testing.T) {
	a := newCA(t)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	cases := map[string][]byte{
		"garbage":  []byte("not a csr"),
		"cert pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1}}),
		"rsa key":  csrPEM(t, rsaKey),
		"p384 key": csrPEM(t, p384),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := a.SignClientCSR(in, "dev", now, time.Hour); !errors.Is(err, ErrBadCSR) {
				t.Fatalf("err = %v, want ErrBadCSR", err)
			}
		})
	}
}

func TestIssueServerCert(t *testing.T) {
	a := newCA(t)
	tc, err := a.IssueServerCert([]string{"mdm.example.com", "127.0.0.1"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(tc.Certificate) != 2 {
		t.Fatalf("chain length = %d, want 2 (leaf + CA)", len(tc.Certificate))
	}
	leaf, err := x509.ParseCertificate(tc.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"mdm.example.com", "127.0.0.1"} {
		opts := x509.VerifyOptions{DNSName: host, Roots: a.Pool(), CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		if _, err := leaf.Verify(opts); err != nil {
			t.Fatalf("verify for %s: %v", host, err)
		}
	}
}

func TestEnvKeyStoreRoundTrip(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	authority, err := LoadOrCreate(ctx, FileKeyStore{Dir: dir}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	certPEM, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadOrCreate(ctx, EnvKeyStore{CertPEM: string(certPEM), KeyPEM: string(keyPEM)}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Cert().Equal(authority.Cert()) {
		t.Fatal("EnvKeyStore loaded a different CA")
	}
}

func TestEnvKeyStoreRefusesToCreate(t *testing.T) {
	_, err := LoadOrCreate(context.Background(), EnvKeyStore{}, time.Now())
	if err == nil {
		t.Fatal("want an error when CA_CERT_PEM and CA_KEY_PEM are unset")
	}
	if !strings.Contains(err.Error(), "CA_CERT_PEM") {
		t.Fatalf("error should name the missing setting, got %v", err)
	}
}

func TestLoadDoesNotCreate(t *testing.T) {
	_, err := Load(context.Background(), FileKeyStore{Dir: t.TempDir()})
	if !errors.Is(err, ErrNotExist) {
		t.Fatalf("want ErrNotExist, got %v", err)
	}
}

// Servers sharing a directory and starting together all end up with the one
// CA, rather than the losers failing to start.
func TestLoadOrCreateRace(t *testing.T) {
	for range 20 {
		ks := FileKeyStore{Dir: t.TempDir()}
		var wg sync.WaitGroup
		cas := make([]*CA, 8)
		errs := make([]error, 8)
		for i := range cas {
			wg.Add(1)
			go func() {
				defer wg.Done()
				cas[i], errs[i] = LoadOrCreate(context.Background(), ks, time.Now())
			}()
		}
		wg.Wait()
		for i := range cas {
			if errs[i] != nil {
				t.Fatalf("server %d: %v", i, errs[i])
			}
			if !bytes.Equal(cas[i].Cert().Raw, cas[0].Cert().Raw) {
				t.Fatalf("server %d has a different CA", i)
			}
		}
	}
}
