// Package attest answers "is this device compliant?" for whatever gates
// access on it: network access control and identity providers asking the
// server, and signed statements a device can present for itself.
package attest

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"time"

	"github.com/google/uuid"

	"retune/internal/server/ca"
	"retune/internal/server/store"
)

// Audience is the aud of every compliance statement, so one can't be
// mistaken for any other token the CA might sign.
const Audience = "retune-device-compliance"

// DefaultTTL is how long a statement is good for. Short: compliance
// changes, and a statement can't be taken back.
const DefaultTTL = time.Hour

// Claims is what a compliance statement says.
type Claims struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"` // the device ID
	Audience  string `json:"aud"`
	IssuedAt  int64  `json:"iat"`
	NotBefore int64  `json:"nbf"`
	Expires   int64  `json:"exp"`
	Hostname  string `json:"hostname"`
	Serial    string `json:"serial,omitempty"`
	// Compliance is the device's overall state: compliant, non_compliant,
	// unknown or not_evaluated.
	Compliance string `json:"compliance"`
	// Compliant is the one answer to act on: an active device, compliant
	// with every policy assigned to it.
	Compliant bool `json:"compliant"`
	// Confirmation binds the statement to the device's certificate (RFC
	// 8705): a relying party that sees the certificate in TLS checks its
	// SHA-256 thumbprint matches, so a statement copied to another machine
	// is no use there.
	Confirmation *Confirmation `json:"cnf,omitempty"`
}

// Confirmation is a statement's cnf claim.
type Confirmation struct {
	CertThumbprint string `json:"x5t#S256"`
}

// DeviceCompliance is one device's answer to a lookup.
type DeviceCompliance struct {
	DeviceID   string     `json:"device_id"`
	Hostname   string     `json:"hostname"`
	Serial     string     `json:"serial"`
	Status     string     `json:"status"`
	Compliance string     `json:"compliance"`
	Compliant  bool       `json:"compliant"`
	LastSeenAt *time.Time `json:"last_seen_at,omitempty"`
}

// Service makes both kinds of answer.
type Service struct {
	Store  *store.Store
	CA     *ca.CA
	Issuer string
	TTL    time.Duration
	Now    func() time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// compliant is the rule both answers use: active, and compliant overall.
// A device with no policy assigned is not_evaluated, and so not compliant:
// nothing has said it is.
func compliant(d store.Device, overall string) bool {
	return d.Status == store.DeviceActive && overall == store.ComplianceCompliant
}

// Lookup finds the devices an identifier matches, with their compliance.
func (s *Service) Lookup(ctx context.Context, by, value string, scope store.DeviceScope) ([]DeviceCompliance, error) {
	q := s.Store.Q()
	devices, err := q.DevicesFor(ctx, by, value, scope)
	if err != nil {
		return nil, err
	}
	ids := make([]uuid.UUID, len(devices))
	for i, d := range devices {
		ids[i] = d.ID
	}
	overall, err := q.ComplianceOverall(ctx, ids)
	if err != nil {
		return nil, err
	}
	out := make([]DeviceCompliance, 0, len(devices))
	for _, d := range devices {
		out = append(out, DeviceCompliance{
			DeviceID: d.ID.String(), Hostname: d.Hostname, Serial: d.Serial, Status: d.Status,
			Compliance: overall[d.ID], Compliant: compliant(d, overall[d.ID]), LastSeenAt: d.LastSeenAt,
		})
	}
	return out, nil
}

// Statement signs a compliance statement for a device, for it to present,
// bound to the certificate it asked with.
func (s *Service) Statement(ctx context.Context, deviceID uuid.UUID, certDER []byte) (string, time.Time, error) {
	q := s.Store.Q()
	d, err := q.GetDevice(ctx, store.DefaultTenantID, deviceID)
	if err != nil {
		return "", time.Time{}, err
	}
	overall, err := q.ComplianceOverall(ctx, []uuid.UUID{deviceID})
	if err != nil {
		return "", time.Time{}, err
	}
	ttl := s.TTL
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	now := s.now().UTC()
	exp := now.Add(ttl)
	claims := Claims{
		Issuer: s.Issuer, Subject: deviceID.String(), Audience: Audience,
		IssuedAt: now.Unix(), NotBefore: now.Unix(), Expires: exp.Unix(),
		Hostname: d.Hostname, Serial: d.Serial,
		Compliance: overall[deviceID], Compliant: compliant(d, overall[deviceID]),
	}
	if len(certDER) > 0 {
		sum := sha256.Sum256(certDER)
		claims.Confirmation = &Confirmation{CertThumbprint: base64.RawURLEncoding.EncodeToString(sum[:])}
	}
	token, err := s.CA.SignJWT(claims)
	return token, exp, err
}
