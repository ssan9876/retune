package enroll

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"retune/internal/protocol"
	"retune/internal/server/ca"
	"retune/internal/server/store"
)

// ErrBadRequest marks invalid input from the caller.
var ErrBadRequest = errors.New("bad request")

// Service creates enrollment tokens and enrolls devices.
type Service struct {
	Store        *store.Store
	CA           *ca.CA
	Now          func() time.Time
	CertValidity time.Duration
}

// TokenOptions configure a new enrollment token.
type TokenOptions struct {
	Label     string
	MaxUses   *int
	ExpiresAt *time.Time
	CreatedBy string
}

// CreateToken stores a new token and returns its plaintext (shown once).
func (s *Service) CreateToken(ctx context.Context, o TokenOptions) (string, store.EnrollmentToken, error) {
	if o.MaxUses != nil && *o.MaxUses <= 0 {
		return "", store.EnrollmentToken{}, fmt.Errorf("%w: max uses must be positive", ErrBadRequest)
	}
	plain, hash, err := GenerateToken()
	if err != nil {
		return "", store.EnrollmentToken{}, err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return "", store.EnrollmentToken{}, err
	}
	tok := store.EnrollmentToken{ID: id, TokenHash: hash, Label: o.Label, MaxUses: o.MaxUses, ExpiresAt: o.ExpiresAt, CreatedBy: o.CreatedBy}
	err = s.Store.InTx(ctx, func(q *store.Queries) error {
		if err := q.CreateEnrollmentToken(ctx, tok); err != nil {
			return err
		}
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: o.CreatedBy, Action: "enrollment_token.created",
			TargetKind: "enrollment_token", TargetID: id.String(),
			Details: map[string]any{"label": o.Label},
		})
	})
	if err != nil {
		return "", store.EnrollmentToken{}, err
	}
	return plain, tok, nil
}

// Enroll validates the token, creates the device, and issues its client
// certificate, all in one transaction.
func (s *Service) Enroll(ctx context.Context, req protocol.EnrollRequest) (protocol.EnrollResponse, error) {
	if strings.TrimSpace(req.Device.Hostname) == "" {
		return protocol.EnrollResponse{}, fmt.Errorf("%w: device hostname is required", ErrBadRequest)
	}
	now := s.Now()
	var resp protocol.EnrollResponse
	err := s.Store.InTx(ctx, func(q *store.Queries) error {
		tok, err := q.GetEnrollmentTokenByHashForUpdate(ctx, HashToken(req.Token))
		if errors.Is(err, store.ErrNotFound) {
			return ErrTokenNotFound
		}
		if err != nil {
			return err
		}
		if err := CheckUsable(tok, now); err != nil {
			return err
		}

		deviceID, err := uuid.NewV7()
		if err != nil {
			return err
		}
		issued, err := s.CA.SignClientCSR([]byte(req.CSRPEM), deviceID.String(), now, s.CertValidity)
		if err != nil {
			return err
		}

		prev, err := q.FindActiveDeviceByHardware(ctx, req.Device.Serial, req.Device.SMBIOSUUID)
		replacing := err == nil
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}

		if err := q.CreateDevice(ctx, store.Device{
			ID:            deviceID,
			Hostname:      req.Device.Hostname,
			Serial:        req.Device.Serial,
			SMBIOSUUID:    req.Device.SMBIOSUUID,
			OSVersion:     req.Device.OSVersion,
			Status:        store.DeviceActive,
			CertSerial:    issued.Serial,
			CertExpiresAt: issued.NotAfter,
			EnrolledAt:    now,
		}); err != nil {
			return err
		}
		details := map[string]any{"token_id": tok.ID.String(), "hostname": req.Device.Hostname}
		if replacing {
			if err := q.MarkDeviceReplaced(ctx, prev.ID, deviceID); err != nil {
				return err
			}
			details["replaced_device_id"] = prev.ID.String()
		}
		if err := q.IncrementTokenUse(ctx, tok.ID); err != nil {
			return err
		}
		if err := q.InsertAudit(ctx, store.AuditEntry{
			Actor: "token:" + tok.ID.String(), Action: "device.enrolled",
			TargetKind: "device", TargetID: deviceID.String(), Details: details,
		}); err != nil {
			return err
		}
		resp = protocol.EnrollResponse{DeviceID: deviceID.String(), CertPEM: string(issued.PEM), CAPEM: string(s.CA.CertPEM())}
		return nil
	})
	if err != nil {
		return protocol.EnrollResponse{}, err
	}
	return resp, nil
}
