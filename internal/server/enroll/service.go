package enroll

import (
	"context"
	"encoding/json"
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
	// RegisteredOnly enrolls only devices registered by serial number.
	RegisteredOnly bool
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
	tok := store.EnrollmentToken{
		ID: id, TokenHash: hash, Label: o.Label, MaxUses: o.MaxUses,
		ExpiresAt: o.ExpiresAt, CreatedBy: o.CreatedBy, CreatedAt: s.Now(), RegisteredOnly: o.RegisteredOnly,
	}
	err = s.Store.InTx(ctx, func(q *store.Queries) error {
		if err := q.CreateEnrollmentToken(ctx, tok); err != nil {
			return err
		}
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: o.CreatedBy, Action: "enrollment_token.created",
			TargetKind: "enrollment_token", TargetID: id.String(),
			Details: map[string]any{"label": o.Label, "registered_only": o.RegisteredOnly},
		})
	})
	if err != nil {
		return "", store.EnrollmentToken{}, err
	}
	return plain, tok, nil
}

// RevokeToken stops a token from being used again.
func (s *Service) RevokeToken(ctx context.Context, id uuid.UUID, actor string) error {
	now := s.Now()
	return s.Store.InTx(ctx, func(q *store.Queries) error {
		tok, err := q.GetEnrollmentToken(ctx, store.DefaultTenantID, id)
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("%w: %s", ErrTokenNotFound, id)
		}
		if err != nil {
			return err
		}
		if err := q.RevokeEnrollmentToken(ctx, store.DefaultTenantID, id, now); err != nil {
			return err
		}
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: actor, Action: "enrollment_token.revoked",
			TargetKind: "enrollment_token", TargetID: id.String(),
			Details: map[string]any{"label": tok.Label},
		})
	})
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
		// A device registered in advance gets its groups and name. The
		// serial is the device's own claim: a registered-only token keeps a
		// leaked token from enrolling any machine, but not one that lies
		// about its serial.
		var reg *store.DeviceRegistration
		if serial := strings.TrimSpace(req.Device.Serial); serial != "" {
			r, err := q.RegistrationForSerial(ctx, serial)
			switch {
			case err == nil:
				reg = &r
			case !errors.Is(err, store.ErrNotFound):
				return err
			}
		}
		if tok.RegisteredOnly && reg == nil {
			return ErrNotRegistered
		}

		deviceID, err := uuid.NewV7()
		if err != nil {
			return err
		}
		issued, err := s.CA.SignClientCSR([]byte(req.CSRPEM), deviceID.String(), now, s.CertValidity)
		if err != nil {
			return err
		}

		// A device already enrolled with the same serial or SMBIOS UUID is
		// most likely this machine before a reimage - but the serial is the
		// enrolling machine's own claim, and serials are not secret. Retiring
		// the match here let anyone holding an enrollment token cut any
		// machine off by quoting its serial, so the match is only recorded:
		// the old record goes stale on its own if it really is gone, and an
		// admin retires it.
		prev, err := q.FindActiveDeviceByHardware(ctx, store.DefaultTenantID, req.Device.Serial, req.Device.SMBIOSUUID)
		sameHardware := err == nil
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
		if sameHardware {
			details["same_hardware_as"] = prev.ID.String()
			details["same_hardware_hostname"] = prev.Hostname
		}
		if err := q.IncrementTokenUse(ctx, store.DefaultTenantID, tok.ID); err != nil {
			return err
		}
		// Every device is in the built-in group from the moment it enrols, so
		// a fleet-wide assignment reaches it on its very first check-in rather
		// than after the next sweep.
		if err := q.AddGroupMember(ctx, store.BuiltinGroupID, deviceID, now); err != nil {
			return err
		}
		if reg != nil {
			if err := provision(ctx, q, *reg, deviceID, req.Device.Hostname, now, details); err != nil {
				return err
			}
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

// renameTTL is how long a provisioning rename waits for its device.
const renameTTL = 7 * 24 * time.Hour

// provision applies a registration to the device it became: into its static
// groups, and renamed if it was given a name. A group since deleted, or made
// dynamic, is skipped: membership of a dynamic group is its rule's to decide.
func provision(ctx context.Context, q *store.Queries, reg store.DeviceRegistration, deviceID uuid.UUID,
	hostname string, now time.Time, details map[string]any) error {
	details["registration_id"] = reg.ID.String()
	var joined []string
	for _, gid := range reg.GroupIDs {
		g, err := q.GetGroup(ctx, store.DefaultTenantID, gid)
		if errors.Is(err, store.ErrNotFound) || (err == nil && g.Kind != store.GroupStatic) {
			continue
		}
		if err != nil {
			return err
		}
		if err := q.AddGroupMember(ctx, gid, deviceID, now); err != nil {
			return err
		}
		joined = append(joined, g.Name)
	}
	details["groups"] = joined
	if reg.DeviceName != "" && !strings.EqualFold(reg.DeviceName, hostname) {
		payload, err := json.Marshal(protocol.RenameComputerPayload{Name: reg.DeviceName})
		if err != nil {
			return err
		}
		if err := q.CreateCommand(ctx, store.Command{
			ID: uuid.Must(uuid.NewV7()), DeviceID: deviceID, Type: protocol.CommandRenameComputer,
			Payload: payload, Status: store.CommandQueued, CreatedBy: "registration:" + reg.ID.String(),
			CreatedAt: now, ExpiresAt: now.Add(renameTTL),
		}); err != nil {
			return err
		}
		details["rename_to"] = reg.DeviceName
	}
	return q.MarkRegistrationEnrolled(ctx, reg.ID, deviceID, now)
}
