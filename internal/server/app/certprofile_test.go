package app_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"testing"
	"time"

	"retune/internal/server/store"
)

func TestCertificateProfile(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "Contoso Root"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyDER, _ := x509.MarshalECPrivateKey(key)
	withKey := cert + string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))

	if status, body := admin.do(http.MethodPost, "/profiles", map[string]any{
		"name": "Contoso root", "settings": []map[string]any{
			{"kind": "certificate", "store": "root", "certificate_pem": cert},
		},
	}); status != http.StatusCreated {
		t.Fatalf("certificate profile: %d %s", status, body)
	}
	if status, _ := admin.do(http.MethodPost, "/profiles", map[string]any{
		"name": "Leaked key", "settings": []map[string]any{
			{"kind": "certificate", "store": "root", "certificate_pem": withKey},
		},
	}); status != http.StatusBadRequest {
		t.Fatalf("a private key: %d", status)
	}
}
