// Package inventory stores the inventory documents agents upload.
package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"time"

	"github.com/google/uuid"

	"retune/internal/protocol"
	"retune/internal/server/store"
)

// ErrBadRequest marks an unacceptable inventory document.
var ErrBadRequest = errors.New("bad request")

// RefreshAfter is how old inventory may get before a new upload is due.
const RefreshAfter = 24 * time.Hour

// MaxSoftwareEntries caps one inventory document's package list.
const MaxSoftwareEntries = 20000

// Membership re-evaluates one device's dynamic group membership. It is an
// interface so that ingesting inventory does not depend on the groups package.
type Membership interface {
	EvaluateDevice(ctx context.Context, deviceID uuid.UUID) error
}

// Service ingests inventory and decides when it is due.
type Service struct {
	Store *store.Store
	Now   func() time.Time
	// Groups, when set, is told after each ingest so that rules over inventory
	// take effect without waiting for the next sweep.
	Groups Membership
	Log    *slog.Logger
}

// Due reports whether the device should collect and upload inventory.
// agentHash is the hash the agent last stored; an empty or differing value
// means the agent and server disagree, so a fresh upload is due.
func (s *Service) Due(ctx context.Context, deviceID uuid.UUID, agentHash string) (bool, error) {
	inv, err := s.Store.Q().GetInventory(ctx, deviceID)
	if errors.Is(err, store.ErrNotFound) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if agentHash != inv.Hash {
		return true, nil
	}
	return s.Now().Sub(inv.ReceivedAt) >= RefreshAfter, nil
}

// Ingest stores a document and returns its hash. Software rows are rewritten
// only when the package list changed.
func (s *Service) Ingest(ctx context.Context, deviceID uuid.UUID, inv protocol.Inventory) (string, error) {
	if len(inv.Software) > MaxSoftwareEntries {
		return "", fmt.Errorf("%w: at most %d software entries", ErrBadRequest, MaxSoftwareEntries)
	}
	hash := protocol.InventoryHash(inv)
	softwareHash := protocol.SoftwareHash(inv.Software)
	data, err := json.Marshal(inv)
	if err != nil {
		return "", err
	}
	now := s.Now()

	err = s.Store.InTx(ctx, func(q *store.Queries) error {
		prev, err := q.GetInventory(ctx, deviceID)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		rewriteSoftware := errors.Is(err, store.ErrNotFound) || prev.SoftwareHash != softwareHash

		if err := q.UpsertInventory(ctx, store.DeviceInventory{
			DeviceID:     deviceID,
			CollectedAt:  inv.CollectedAt,
			ReceivedAt:   now,
			Hash:         hash,
			SoftwareHash: softwareHash,
			Data:         data,
			RAMGB:        gigabytes(inv.Hardware.RAMBytes),
			DiskFreeGB:   gigabytes(freeBytes(inv.Disks)),
		}); err != nil {
			return err
		}
		if rewriteSoftware {
			rows := make([]store.Software, 0, len(inv.Software))
			for _, sw := range inv.Software {
				rows = append(rows, store.Software{
					Name: sw.Name, Version: sw.Version, Publisher: sw.Publisher,
					InstallDate: sw.InstallDate, Scope: sw.Scope,
				})
			}
			if err := q.ReplaceSoftware(ctx, deviceID, rows); err != nil {
				return err
			}
		}
		return q.UpdateDeviceHardware(ctx, deviceID, store.HardwareInfo{
			Hostname:     inv.Hostname,
			Serial:       inv.Hardware.Serial,
			SMBIOSUUID:   inv.Hardware.SMBIOSUUID,
			OSVersion:    strings.TrimSpace(inv.OS.Name + " " + inv.OS.Version),
			OSBuild:      inv.OS.Build,
			Manufacturer: inv.Hardware.Manufacturer,
			Model:        inv.Hardware.Model,
		})
	})
	if err != nil {
		return "", err
	}
	// Membership is refreshed after the inventory is safely stored, and a
	// failure here is logged rather than returned: the write succeeded, and
	// failing the agent's request would make it retry an upload that worked.
	// The 15-minute sweep is the backstop.
	if s.Groups != nil {
		if err := s.Groups.EvaluateDevice(ctx, deviceID); err != nil {
			s.logger().Warn("re-evaluate group membership", "device_id", deviceID, "error", err)
		}
	}
	return hash, nil
}

func (s *Service) logger() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

func freeBytes(disks []protocol.Disk) uint64 {
	var total uint64
	for _, d := range disks {
		total += d.FreeBytes
	}
	return total
}

func gigabytes(b uint64) float64 {
	return math.Round(float64(b)/(1<<30)*100) / 100
}
