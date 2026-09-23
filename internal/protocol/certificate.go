package protocol

import (
	"crypto/sha1" //nolint:gosec // a certificate's thumbprint is SHA-1 by Windows' definition
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// KindCertificate puts a certificate into one of the machine's trust stores.
const KindCertificate = "certificate"

// CertificateStores are the stores a certificate setting can name, and the
// Windows store each one is under Cert:\LocalMachine.
var CertificateStores = map[string]string{
	"root":              "Root",             // trusted root authorities
	"ca":                "CA",               // intermediate authorities
	"trusted_publisher": "TrustedPublisher", // publishers whose signed code is trusted
}

// MaxCertificatePEMBytes bounds a certificate setting.
const MaxCertificatePEMBytes = 16 << 10

// ErrPrivateKey is returned for PEM that carries a private key: a trust store
// takes certificates, and a private key pasted into a profile would be sent
// to every assigned machine.
var ErrPrivateKey = errors.New("the PEM contains a private key; paste only the certificate")

// ParseCertificatePEM reads exactly one certificate from PEM text and
// returns it with its DER bytes. Anything else in the text is refused.
func ParseCertificatePEM(text string) (*x509.Certificate, []byte, error) {
	if len(text) > MaxCertificatePEMBytes {
		return nil, nil, fmt.Errorf("a certificate can be at most %d KiB of PEM", MaxCertificatePEMBytes>>10)
	}
	if strings.Contains(text, "PRIVATE KEY") {
		return nil, nil, ErrPrivateKey
	}
	rest := []byte(strings.TrimSpace(text))
	var der []byte
	for len(rest) > 0 {
		block, next := pem.Decode(rest)
		if block == nil {
			return nil, nil, errors.New("certificate_pem is not PEM (it should start -----BEGIN CERTIFICATE-----)")
		}
		if block.Type != "CERTIFICATE" {
			return nil, nil, fmt.Errorf("certificate_pem has a %s block; only CERTIFICATE is taken", block.Type)
		}
		if der != nil {
			return nil, nil, errors.New("certificate_pem has more than one certificate; use one setting each")
		}
		der = block.Bytes
		rest = []byte(strings.TrimSpace(string(next)))
	}
	if der == nil {
		return nil, nil, errors.New("certificate_pem is empty")
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("the certificate doesn't parse: %w", err)
	}
	return cert, der, nil
}

// Thumbprint is how Windows names a certificate: the SHA-1 of its DER, in
// upper-case hex.
func Thumbprint(der []byte) string {
	sum := sha1.Sum(der) //nolint:gosec
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// CertificateThumbprint is the thumbprint of a setting's certificate, or ""
// if it doesn't parse.
func (s Setting) CertificateThumbprint() string {
	_, der, err := ParseCertificatePEM(s.CertificatePEM)
	if err != nil {
		return ""
	}
	return Thumbprint(der)
}

func (s Setting) validateCertificate() error {
	if _, ok := CertificateStores[s.Store]; !ok {
		return fmt.Errorf("%w: store must be root, ca or trusted_publisher", ErrBadSetting)
	}
	if _, _, err := ParseCertificatePEM(s.CertificatePEM); err != nil {
		return fmt.Errorf("%w: %v", ErrBadSetting, err)
	}
	return nil
}
