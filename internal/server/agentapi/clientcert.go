package agentapi

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
)

// CertError is a client-certificate failure carrying the response to send.
type CertError struct {
	Status  int
	Code    string
	Message string
}

func (e CertError) Error() string { return e.Message }

// TLSClientCert reads the certificate from the request's own TLS handshake.
// It returns (nil, nil) when the client presented none, which is how /enroll
// stays reachable.
func TLSClientCert(r *http.Request) (*x509.Certificate, error) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
		return nil, nil
	}
	return r.TLS.VerifiedChains[0][0], nil
}

// HeaderClientCert reads the certificate from a header set by a trusted
// reverse proxy, for TLS_MODE=behind-proxy. The proxy delivers the bytes; it
// never supplies a verdict, so the certificate is verified against pool here.
func HeaderClientCert(header string, trusted []netip.Prefix, pool *x509.CertPool) func(*http.Request) (*x509.Certificate, error) {
	return func(r *http.Request) (*x509.Certificate, error) {
		raw := r.Header.Get(header)
		if !peerTrusted(r.RemoteAddr, trusted) {
			if raw != "" {
				// Someone reached the server directly and asserted a client
				// certificate. That is an attack, not a missing certificate.
				return nil, CertError{http.StatusForbidden, "untrusted_proxy",
					"client certificate headers are only accepted from a trusted proxy"}
			}
			return nil, nil
		}
		if raw == "" {
			return nil, nil
		}
		cert, err := parseCertHeader(raw)
		if err != nil {
			return nil, CertError{http.StatusUnauthorized, "client_cert_invalid", err.Error()}
		}
		if _, err := cert.Verify(x509.VerifyOptions{
			Roots:     pool,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}); err != nil {
			return nil, CertError{http.StatusUnauthorized, "client_cert_invalid",
				"client certificate was not issued by this server"}
		}
		return cert, nil
	}
}

func peerTrusted(remoteAddr string, trusted []netip.Prefix) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	for _, p := range trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// parseCertHeader accepts a PEM certificate, URL-encoded (nginx's
// ssl_client_escaped_cert, and what Caddy is usually configured to send) or
// literal.
func parseCertHeader(raw string) (*x509.Certificate, error) {
	if !strings.Contains(raw, "BEGIN CERTIFICATE") {
		decoded, err := url.QueryUnescape(raw)
		if err != nil {
			return nil, errors.New("client certificate header is not valid URL encoding")
		}
		raw = decoded
	}
	block, _ := pem.Decode([]byte(raw))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("client certificate header is not a PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.New("client certificate header is not a valid certificate")
	}
	return cert, nil
}
