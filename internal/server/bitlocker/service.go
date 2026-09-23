// Package bitlocker escrows BitLocker recovery keys and hands them back, once,
// to an administrator who asks for one on the record.
package bitlocker

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"retune/internal/server/secrets"
	"retune/internal/server/store"
)

var (
	// ErrNotFound is returned when no key is escrowed for what was asked.
	ErrNotFound = errors.New("no recovery key")
	// ErrBadRequest is returned for input the caller can fix.
	ErrBadRequest = errors.New("bad request")
)

// MaxRecoveryPasswordBytes is generous for a recovery password, which is a
// fixed shape, and small enough that nothing large lands in the column.
const MaxRecoveryPasswordBytes = 256

// Service owns escrowed recovery keys.
type Service struct {
	Store *store.Store
	Key   *secrets.Key
	Now   func() time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// EscrowContext binds a ciphertext to the device and volume it came from, so a row
// copied to another device does not decrypt.
func EscrowContext(deviceID uuid.UUID, volumeID string) []byte {
	return []byte(deviceID.String() + "/" + strings.ToUpper(volumeID))
}

// Escrow stores a recovery password for one volume.
func (s *Service) Escrow(ctx context.Context, deviceID uuid.UUID, volumeID, method, recoveryPassword string) error {
	volumeID = strings.TrimSpace(volumeID)
	recoveryPassword = strings.TrimSpace(recoveryPassword)
	switch {
	case volumeID == "":
		return fmt.Errorf("%w: a recovery key needs a volume", ErrBadRequest)
	case recoveryPassword == "":
		return fmt.Errorf("%w: a recovery key cannot be empty", ErrBadRequest)
	case len(recoveryPassword) > MaxRecoveryPasswordBytes:
		return fmt.Errorf("%w: a recovery key may be at most %d bytes", ErrBadRequest, MaxRecoveryPasswordBytes)
	}
	if s.Key == nil {
		return errors.New("this server has no key to protect recovery keys with")
	}

	ciphertext, nonce, err := s.Key.Seal([]byte(recoveryPassword), EscrowContext(deviceID, volumeID))
	if err != nil {
		return err
	}
	now := s.now()
	return s.Store.InTx(ctx, func(q *store.Queries) error {
		if err := q.UpsertBitLockerKey(ctx, store.BitLockerKey{
			ID: uuid.Must(uuid.NewV7()), DeviceID: deviceID, VolumeID: volumeID,
			Method: method, Ciphertext: ciphertext, Nonce: nonce, CreatedAt: now,
		}); err != nil {
			return err
		}
		// Escrowing is recorded, but the key itself never appears in the audit
		// log; only that one arrived.
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: "device:" + deviceID.String(), Action: "bitlocker_key.escrowed",
			TargetKind: "device", TargetID: deviceID.String(),
			Details: map[string]any{"volume_id": volumeID, "method": method},
		})
	})
}

// Has reports whether a volume's key is already escrowed.
func (s *Service) Has(ctx context.Context, deviceID uuid.UUID, volumeID string) (bool, error) {
	return s.Store.Q().HasBitLockerKey(ctx, store.DefaultTenantID, deviceID, strings.TrimSpace(volumeID))
}

// List returns the escrowed volumes of a device, without any keys.
func (s *Service) List(ctx context.Context, deviceID uuid.UUID) ([]store.BitLockerKey, error) {
	return s.Store.Q().ListBitLockerKeys(ctx, deviceID)
}

// Reveal returns one recovery password and records who asked for it. Every
// successful reveal is audited: that is the point of making it its own act
// rather than a field on a listing.
func (s *Service) Reveal(ctx context.Context, id uuid.UUID, actor, reason string) (store.BitLockerKey, string, error) {
	if s.Key == nil {
		return store.BitLockerKey{}, "", errors.New("this server has no key to read recovery keys with")
	}
	k, err := s.Store.Q().GetBitLockerKey(ctx, store.DefaultTenantID, id)
	if errors.Is(err, store.ErrNotFound) {
		return store.BitLockerKey{}, "", ErrNotFound
	}
	if err != nil {
		return store.BitLockerKey{}, "", err
	}

	plaintext, err := s.Key.Open(k.Ciphertext, k.Nonce, EscrowContext(k.DeviceID, k.VolumeID))
	if err != nil {
		return store.BitLockerKey{}, "", err
	}

	details := map[string]any{"volume_id": k.VolumeID, "hostname": k.Hostname}
	if strings.TrimSpace(reason) != "" {
		details["reason"] = strings.TrimSpace(reason)
	}
	if err := s.Store.Q().InsertAudit(ctx, store.AuditEntry{
		Actor: actor, Action: "bitlocker_key.viewed",
		TargetKind: "device", TargetID: k.DeviceID.String(), Details: details,
	}); err != nil {
		// If it cannot be recorded, it is not handed over: an unaudited reveal
		// is exactly what this endpoint exists to prevent.
		return store.BitLockerKey{}, "", fmt.Errorf("record the reveal: %w", err)
	}
	return k, string(plaintext), nil
}
