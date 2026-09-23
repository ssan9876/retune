// Package laps escrows the local administrator passwords agents set, and
// hands one back to an administrator who asks for it on the record.
package laps

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"retune/internal/protocol"
	"retune/internal/server/secrets"
	"retune/internal/server/store"
)

var (
	// ErrNotFound is returned for a password, or a command, that isn't there
	// for this caller.
	ErrNotFound = errors.New("no such password")
	// ErrBadRequest is returned for input the caller can fix.
	ErrBadRequest = errors.New("bad request")
	// ErrConflict is returned when a command can't take an escrow in its
	// state.
	ErrConflict = errors.New("conflict")
)

const maxReason = 500

// Service owns escrowed local admin passwords.
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

// SealContext binds a ciphertext to its device and account, so a row copied
// to another device or account doesn't decrypt.
func SealContext(deviceID uuid.UUID, account string) []byte {
	return []byte("admin-password:" + deviceID.String() + "/" + strings.ToUpper(account))
}

// Escrow stores the password a device is about to set for a running
// rotate_local_admin_password command of its own. The device sets it only
// once this succeeds.
func (s *Service) Escrow(ctx context.Context, deviceID uuid.UUID, req protocol.AdminPasswordEscrowRequest) error {
	commandID, err := uuid.Parse(req.CommandID)
	if err != nil {
		return ErrNotFound
	}
	account := strings.TrimSpace(req.Account)
	switch {
	case account == "" || len(account) > 256:
		return fmt.Errorf("%w: an escrowed password needs its account", ErrBadRequest)
	case utf8.RuneCountInString(req.Password) < protocol.MinAdminPasswordLength ||
		utf8.RuneCountInString(req.Password) > protocol.MaxAdminPasswordLength:
		return fmt.Errorf("%w: the password must be %d to %d characters", ErrBadRequest,
			protocol.MinAdminPasswordLength, protocol.MaxAdminPasswordLength)
	}
	if s.Key == nil {
		return errors.New("this server has no key to protect passwords with")
	}
	c, err := s.Store.Q().GetCommand(ctx, store.DefaultTenantID, commandID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && c.DeviceID != deviceID) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if c.Type != protocol.CommandRotateAdminPassword {
		return fmt.Errorf("%w: a %s command sets no password", ErrConflict, c.Type)
	}
	if c.Status != store.CommandRunning {
		return fmt.Errorf("%w: the command is %s, not running", ErrConflict, c.Status)
	}
	ciphertext, nonce, err := s.Key.Seal([]byte(req.Password), SealContext(deviceID, account))
	if err != nil {
		return err
	}
	return s.Store.InTx(ctx, func(q *store.Queries) error {
		if err := q.UpsertPendingAdminPassword(ctx, store.AdminPassword{
			ID: uuid.Must(uuid.NewV7()), DeviceID: deviceID, Account: account,
			Ciphertext: ciphertext, Nonce: nonce, CommandID: commandID, CreatedAt: s.now(),
		}); err != nil {
			return err
		}
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: "device:" + deviceID.String(), Action: "local_admin_password.escrowed",
			TargetKind: "device", TargetID: deviceID.String(),
			Details: map[string]any{"account": account, "command_id": commandID.String()},
		})
	})
}

// Settle is the commands service's completion hook: a command's pending
// password becomes active when it succeeded, abandoned otherwise. It runs in
// the transaction that records the result.
func Settle(ctx context.Context, q *store.Queries, c store.Command, status string, at time.Time) error {
	if c.Type != protocol.CommandRotateAdminPassword {
		return nil
	}
	return q.SettleAdminPassword(ctx, c.ID, status == protocol.ResultSucceeded, at)
}

// List returns a device's escrowed passwords, without the secrets.
func (s *Service) List(ctx context.Context, deviceID uuid.UUID) ([]store.AdminPassword, error) {
	return s.Store.Q().ListAdminPasswords(ctx, deviceID)
}

// Get returns one escrowed password's record, without opening it.
func (s *Service) Get(ctx context.Context, id uuid.UUID) (store.AdminPassword, error) {
	p, err := s.Store.Q().GetAdminPassword(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return p, ErrNotFound
	}
	return p, err
}

// Reveal returns one password and records who asked, and why. A reason is
// required. If the audit entry can't be written, nothing is handed over.
func (s *Service) Reveal(ctx context.Context, id uuid.UUID, actor, reason string) (store.AdminPassword, string, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return store.AdminPassword{}, "", fmt.Errorf("%w: say why you need the password", ErrBadRequest)
	}
	if len(reason) > maxReason {
		return store.AdminPassword{}, "", fmt.Errorf("%w: the reason must be at most %d characters", ErrBadRequest, maxReason)
	}
	if s.Key == nil {
		return store.AdminPassword{}, "", errors.New("this server has no key to read passwords with")
	}
	p, err := s.Get(ctx, id)
	if err != nil {
		return store.AdminPassword{}, "", err
	}
	plaintext, err := s.Key.Open(p.Ciphertext, p.Nonce, SealContext(p.DeviceID, p.Account))
	if err != nil {
		return store.AdminPassword{}, "", err
	}
	if err := s.Store.Q().InsertAudit(ctx, store.AuditEntry{
		Actor: actor, Action: "local_admin_password.revealed", TargetKind: "device", TargetID: p.DeviceID.String(),
		Details: map[string]any{"account": p.Account, "hostname": p.Hostname, "state": p.State, "reason": reason},
	}); err != nil {
		return store.AdminPassword{}, "", fmt.Errorf("record the reveal: %w", err)
	}
	p.Ciphertext, p.Nonce = nil, nil
	return p, string(plaintext), nil
}
