// Package inventory stores the inventory documents agents upload.
package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

// Service ingests inventory and decides when it is due.
type Service struct {
	Store *store.Store
	Now   func() time.Time
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
	return hash, nil
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
