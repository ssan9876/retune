// Package identity stores the agent's enrolled device identity on disk.
package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// ErrNotEnrolled is returned by Load when no identity exists.
var ErrNotEnrolled = errors.New("agent is not enrolled")

// Identity is everything the agent needs to talk to its server.
type Identity struct {
	DeviceID  string            `json:"device_id"`
	ServerURL string            `json:"server_url"`
	ServerPin string            `json:"server_pin,omitempty"`
	CertPEM   string            `json:"cert_pem"`
	CAPEM     string            `json:"ca_pem"`
	Key       *ecdsa.PrivateKey `json:"-"`
}

// TLSCertificate returns the client certificate for mTLS.
func (id *Identity) TLSCertificate() (tls.Certificate, error) {
	b, _ := pem.Decode([]byte(id.CertPEM))
	if b == nil || b.Type != "CERTIFICATE" {
		return tls.Certificate{}, errors.New("identity certificate is not PEM CERTIFICATE")
	}
	return tls.Certificate{Certificate: [][]byte{b.Bytes}, PrivateKey: id.Key}, nil
}

// Store persists an Identity as identity.json plus a sealed key.bin.
type Store struct {
	Dir  string
	Keys KeyProvider
}

func (s Store) Save(id *Identity) error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	der, err := x509.MarshalECPrivateKey(id.Key)
	if err != nil {
		return err
	}
	sealed, err := s.Keys.Protect(der)
	if err != nil {
		return err
	}
	meta, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(s.Dir, "key.bin"), sealed); err != nil {
		return err
	}
	return writeAtomic(filepath.Join(s.Dir, "identity.json"), meta)
}

func (s Store) Load() (*Identity, error) {
	meta, err := os.ReadFile(filepath.Join(s.Dir, "identity.json"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotEnrolled
	}
	if err != nil {
		return nil, err
	}
	var id Identity
	if err := json.Unmarshal(meta, &id); err != nil {
		return nil, fmt.Errorf("parse identity.json: %w", err)
	}
	sealed, err := os.ReadFile(filepath.Join(s.Dir, "key.bin"))
	if err != nil {
		return nil, err
	}
	der, err := s.Keys.Unprotect(sealed)
	if err != nil {
		return nil, err
	}
	if id.Key, err = x509.ParseECPrivateKey(der); err != nil {
		return nil, fmt.Errorf("parse device key: %w", err)
	}
	return &id, nil
}

// NewKeyAndCSR generates the device keypair and a CSR for enrollment.
func NewKeyAndCSR(hostname string) (*ecdsa.PrivateKey, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: hostname}}, key)
	if err != nil {
		return nil, "", err
	}
	return key, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), nil
}

func writeAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
