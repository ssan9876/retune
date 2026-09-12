// Package devices changes device lifecycle status.
package devices

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/google/uuid"

	"retune/internal/server/store"
)

var (
	ErrNotFound          = errors.New("device not found")
	ErrInvalidTransition = errors.New("invalid device status change")
)

// Service retires and unenrolls devices.
type Service struct {
	Store *store.Store
}

// Retire stops an active device from checking in; its agent idles.
func (s *Service) Retire(ctx context.Context, id uuid.UUID, actor string) error {
	return s.transition(ctx, id, actor, store.DeviceRetired, "device.retired", store.DeviceActive)
}

// Unenroll tells the agent to delete its identity and local state.
func (s *Service) Unenroll(ctx context.Context, id uuid.UUID, actor string) error {
	return s.transition(ctx, id, actor, store.DeviceUnenrolled, "device.unenrolled", store.DeviceActive, store.DeviceRetired)
}

func (s *Service) transition(ctx context.Context, id uuid.UUID, actor, to, action string, from ...string) error {
	return s.Store.InTx(ctx, func(q *store.Queries) error {
		d, err := q.GetDevice(ctx, id)
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("%w: %s", ErrNotFound, id)
		}
		if err != nil {
			return err
		}
		if !slices.Contains(from, d.Status) {
			return fmt.Errorf("%w: %s cannot go from %s to %s", ErrInvalidTransition, d.Hostname, d.Status, to)
		}
		if err := q.SetDeviceStatus(ctx, id, to); err != nil {
			return err
		}
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: actor, Action: action, TargetKind: "device", TargetID: id.String(),
			Details: map[string]any{"from": d.Status},
		})
	})
}
