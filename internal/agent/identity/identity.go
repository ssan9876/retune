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
	"time"
)

// ErrNotEnrolled is returned by Load when no identity exists.
var ErrNotEnrolled = errors.New("agent is not enrolled")

// legacyKeyFile is the separate sealed-key file written before M2.
const legacyKeyFile = "key.bin"

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

// CertNotAfter is when the current client certificate expires.
func (id *Identity) CertNotAfter() (time.Time, error) {
	b, _ := pem.Decode([]byte(id.CertPEM))
	if b == nil || b.Type != "CERTIFICATE" {
		return time.Time{}, errors.New("identity certificate is not PEM CERTIFICATE")
	}
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse identity certificate: %w", err)
	}
	return cert.NotAfter, nil
}

// Store persists an Identity as identity.json plus a sealed key.bin.
type Store struct {
	Dir  string
	Keys KeyProvider
}

// fileFormat is identity.json on disk: the identity plus its sealed key, so a
// renewal replaces key and certificate in one atomic write.
type fileFormat struct {
	Identity
	SealedKey []byte `json:"sealed_key"`
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
	meta, err := json.MarshalIndent(fileFormat{Identity: *id, SealedKey: sealed}, "", "  ")
	if err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(s.Dir, "identity.json"), meta); err != nil {
		return err
	}
	// Clean up the pre-M2 layout.
	if err := os.Remove(filepath.Join(s.Dir, legacyKeyFile)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

func (s Store) Load() (*Identity, error) {
	meta, err := os.ReadFile(filepath.Join(s.Dir, "identity.json"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotEnrolled
	}
	if err != nil {
		return nil, err
	}
	var f fileFormat
	if err := json.Unmarshal(meta, &f); err != nil {
		return nil, fmt.Errorf("parse identity.json: %w", err)
	}
	sealed := f.SealedKey
	if len(sealed) == 0 {
		if sealed, err = os.ReadFile(filepath.Join(s.Dir, legacyKeyFile)); err != nil {
			return nil, fmt.Errorf("read device key: %w", err)
		}
	}
	der, err := s.Keys.Unprotect(sealed)
	if err != nil {
		return nil, err
	}
	id := f.Identity
	if id.Key, err = x509.ParseECPrivateKey(der); err != nil {
		return nil, fmt.Errorf("parse device key: %w", err)
	}
	return &id, nil
}

// Delete removes the stored identity, for unenrollment.
func (s Store) Delete() error {
	for _, name := range []string{"identity.json", legacyKeyFile} {
		if err := os.Remove(filepath.Join(s.Dir, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
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
