// Package ca is Retune's internal certificate authority.
package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net"
	"time"
)

// ErrBadCSR is returned for unparseable or unacceptable CSRs.
var ErrBadCSR = errors.New("invalid certificate signing request")

// CA signs device client certificates and the self-signed server certificate.
type CA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// IssuedCert is a signed client certificate.
type IssuedCert struct {
	PEM      []byte
	Serial   string // lowercase hex
	NotAfter time.Time
}

// LoadOrCreate loads the CA from ks, creating and saving a new one if none exists.
func LoadOrCreate(ctx context.Context, ks KeyStore, now time.Time) (*CA, error) {
	certPEM, keyPEM, err := ks.Load(ctx)
	if errors.Is(err, ErrNotExist) {
		c, certPEM, keyPEM, err := create(now)
		if err != nil {
			return nil, err
		}
		if err := ks.Save(ctx, certPEM, keyPEM); err != nil {
			if errors.Is(err, fs.ErrExist) {
				// Another server sharing this directory made one first: use
				// theirs, once they have finished writing it.
				return awaitOther(ctx, ks)
			}
			return nil, fmt.Errorf("save CA: %w", err)
		}
		return c, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load CA: %w", err)
	}
	c, err := parse(certPEM, keyPEM)
	if err != nil {
		// Written by an older version, or by a server beside this one that
		// is part-way through: give it the few seconds it needs.
		return awaitOther(ctx, ks)
	}
	return c, nil
}

// awaitOther loads the CA another server is creating, waiting a few
// seconds for it to finish writing.
func awaitOther(ctx context.Context, ks KeyStore) (*CA, error) {
	var lastErr error
	for range 50 {
		certPEM, keyPEM, err := ks.Load(ctx)
		if err == nil {
			c, err := parse(certPEM, keyPEM)
			if err == nil {
				return c, nil
			}
			lastErr = err
		} else {
			lastErr = err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return nil, fmt.Errorf("another server was creating the CA, and it never became readable: %w", lastErr)
}

// Load returns the existing CA without creating one, for commands that only
// want to read it. It returns ErrNotExist when none has been created yet.
func Load(ctx context.Context, ks KeyStore) (*CA, error) {
	certPEM, keyPEM, err := ks.Load(ctx)
	if err != nil {
		return nil, err
	}
	return parse(certPEM, keyPEM)
}

func create(now time.Time) (*CA, []byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Retune Internal CA", Organization: []string{"Retune"}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return &CA{cert: cert, key: key}, certPEM, keyPEM, nil
}

func parse(certPEM, keyPEM []byte) (*CA, error) {
	cb, _ := pem.Decode(certPEM)
	if cb == nil || cb.Type != "CERTIFICATE" {
		return nil, errors.New("CA certificate is not PEM CERTIFICATE")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}
	if !cert.IsCA {
		return nil, errors.New("stored CA certificate is not a CA")
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil || kb.Type != "EC PRIVATE KEY" {
		return nil, errors.New("CA key is not PEM EC PRIVATE KEY")
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA key: %w", err)
	}
	return &CA{cert: cert, key: key}, nil
}

func randomSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

func (c *CA) Cert() *x509.Certificate { return c.cert }

func (c *CA) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.cert.Raw})
}

func (c *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c.cert)
	return p
}

// SignClientCSR issues a ClientAuth certificate with CN = deviceID.
// Only ECDSA P-256 keys are accepted.
func (c *CA) SignClientCSR(csrPEM []byte, deviceID string, now time.Time, validity time.Duration) (IssuedCert, error) {
	b, _ := pem.Decode(csrPEM)
	if b == nil || b.Type != "CERTIFICATE REQUEST" {
		return IssuedCert{}, fmt.Errorf("%w: not a PEM CERTIFICATE REQUEST", ErrBadCSR)
	}
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil {
		return IssuedCert{}, fmt.Errorf("%w: %v", ErrBadCSR, err)
	}
	if err := csr.CheckSignature(); err != nil {
		return IssuedCert{}, fmt.Errorf("%w: %v", ErrBadCSR, err)
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return IssuedCert{}, fmt.Errorf("%w: key must be ECDSA P-256", ErrBadCSR)
	}
	serial, err := randomSerial()
	if err != nil {
		return IssuedCert{}, err
	}
	notAfter := now.Add(validity).Truncate(time.Second)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: deviceID},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, pub, c.key)
	if err != nil {
		return IssuedCert{}, err
	}
	return IssuedCert{
		PEM:      pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		Serial:   serial.Text(16),
		NotAfter: notAfter,
	}, nil
}

// IssueServerCert creates a fresh ServerAuth certificate for hosts (DNS names
// or IPs) signed by the CA. The returned chain includes the CA so agents
// that pin the CA fingerprint can find it.
func (c *CA) IssueServerCert(hosts []string, now time.Time) (tls.Certificate, error) {
	if len(hosts) == 0 {
		return tls.Certificate{}, errors.New("at least one host is required")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := randomSerial()
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hosts[0]},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der, c.cert.Raw}, PrivateKey: key}, nil
}
