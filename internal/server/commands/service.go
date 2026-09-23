// Package commands queues ad-hoc device commands and records their results.
package commands

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"retune/internal/protocol"
	"retune/internal/server/store"
)

var (
	ErrBadRequest      = errors.New("bad request")
	ErrNotFound        = errors.New("command not found")
	ErrDeviceNotActive = errors.New("device is not active")
)

// Timing defaults.
const (
	DefaultTTL           = 7 * 24 * time.Hour
	DefaultScriptTimeout = 10 * time.Minute
	MaxScriptTimeout     = 24 * time.Hour
	maxRestartMessage    = 512
)

// Service owns the command queue.
type Service struct {
	Store *store.Store
	Now   func() time.Time
	// ArtifactDir holds files commands produce, such as collect_logs'
	// archives. Left empty, uploads are refused.
	ArtifactDir string
}

// QueueOptions describe a command to queue.
type QueueOptions struct {
	DeviceID  uuid.UUID
	Type      string
	Payload   json.RawMessage
	CreatedBy string
	TTL       time.Duration

	// ConfirmHostname and Reason are required for a wipe: the hostname the
	// administrator typed, which must be the device's, and why.
	ConfirmHostname string
	Reason          string
}

// WipeTTL is how long a wipe waits for its device. A lost machine that comes
// back online a week later must not wipe itself on an order nobody
// remembers giving.
const WipeTTL = 24 * time.Hour

const maxWipeReason = 500

// Queue validates and stores a command for an active device.
func (s *Service) Queue(ctx context.Context, o QueueOptions) (store.Command, error) {
	payload, err := normalizePayload(o.Type, o.Payload)
	if err != nil {
		return store.Command{}, err
	}
	now := s.Now()
	ttl := o.TTL
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	wipe := o.Type == protocol.CommandWipe
	reason := strings.TrimSpace(o.Reason)
	if wipe {
		if reason == "" {
			return store.Command{}, fmt.Errorf("%w: a wipe needs a reason", ErrBadRequest)
		}
		if len(reason) > maxWipeReason {
			return store.Command{}, fmt.Errorf("%w: the reason must be at most %d characters", ErrBadRequest, maxWipeReason)
		}
		if ttl > WipeTTL {
			ttl = WipeTTL
		}
	}
	id, err := uuid.NewV7()
	if err != nil {
		return store.Command{}, err
	}
	c := store.Command{
		ID: id, DeviceID: o.DeviceID, Type: o.Type, Payload: payload, Status: store.CommandQueued,
		CreatedBy: o.CreatedBy, CreatedAt: now, ExpiresAt: now.Add(ttl),
	}
	err = s.Store.InTx(ctx, func(q *store.Queries) error {
		d, err := q.GetDevice(ctx, store.DefaultTenantID, o.DeviceID)
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("%w: no device %s", ErrNotFound, o.DeviceID)
		}
		if err != nil {
			return err
		}
		if d.Status != store.DeviceActive {
			return fmt.Errorf("%w: %s is %s", ErrDeviceNotActive, d.Hostname, d.Status)
		}
		if wipe && !strings.EqualFold(strings.TrimSpace(o.ConfirmHostname), d.Hostname) {
			return fmt.Errorf("%w: to wipe this device, confirm_hostname must be its hostname, %s", ErrBadRequest, d.Hostname)
		}
		if err := q.CreateCommand(ctx, c); err != nil {
			return err
		}
		action, details := "command.queued", map[string]any{"device_id": o.DeviceID.String(), "type": o.Type}
		if wipe {
			action = "command.wipe_queued"
			details["hostname"], details["reason"] = d.Hostname, reason
			var wp protocol.WipePayload
			_ = json.Unmarshal(payload, &wp) // canonical, from normalizePayload
			details["protected"] = wp.Protected
		}
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: o.CreatedBy, Action: action, TargetKind: "command", TargetID: id.String(),
			Details: details,
		})
	})
	if err != nil {
		return store.Command{}, err
	}
	return c, nil
}

// normalizePayload validates a payload and returns its canonical JSON.
func normalizePayload(typ string, raw json.RawMessage) ([]byte, error) {
	switch typ {
	case protocol.CommandRunPowerShell:
		var p protocol.RunPowerShellPayload
		if err := decodePayload(raw, &p); err != nil {
			return nil, err
		}
		if strings.TrimSpace(p.Script) == "" {
			return nil, fmt.Errorf("%w: script is required", ErrBadRequest)
		}
		switch {
		case p.TimeoutSeconds == 0:
			p.TimeoutSeconds = int(DefaultScriptTimeout / time.Second)
		case p.TimeoutSeconds < 0 || p.TimeoutSeconds > int(MaxScriptTimeout/time.Second):
			return nil, fmt.Errorf("%w: timeout_seconds must be between 1 and %d", ErrBadRequest, int(MaxScriptTimeout/time.Second))
		}
		return json.Marshal(p)
	case protocol.CommandRestart:
		var p protocol.RestartPayload
		if err := decodePayload(raw, &p); err != nil {
			return nil, err
		}
		if p.DelaySeconds < 0 || p.DelaySeconds > 86400 {
			return nil, fmt.Errorf("%w: delay_seconds must be between 0 and 86400", ErrBadRequest)
		}
		if len(p.Message) > maxRestartMessage {
			return nil, fmt.Errorf("%w: message must be at most %d characters", ErrBadRequest, maxRestartMessage)
		}
		return json.Marshal(p)
	case protocol.CommandRefreshInventory, protocol.CommandLock:
		return []byte(`{}`), nil
	case protocol.CommandCollectLogs:
		var p protocol.CollectLogsPayload
		if err := decodePayload(raw, &p); err != nil {
			return nil, err
		}
		if p.Hours == 0 {
			p.Hours = protocol.DefaultLogHours
		}
		if p.Hours < protocol.MinLogHours || p.Hours > protocol.MaxLogHours {
			return nil, fmt.Errorf("%w: hours must be between %d and %d", ErrBadRequest, protocol.MinLogHours, protocol.MaxLogHours)
		}
		return json.Marshal(p)
	case protocol.CommandWipe:
		var p protocol.WipePayload
		if err := decodePayload(raw, &p); err != nil {
			return nil, err
		}
		return json.Marshal(p)
	default:
		return nil, fmt.Errorf("%w: unsupported command type %q", ErrBadRequest, typ)
	}
}

func decodePayload(raw json.RawMessage, v any) error {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("%w: %v", ErrBadRequest, err)
	}
	return nil
}

// Deliver returns the commands a device still owes, marking queued ones as
// delivered. Commands past their TTL expire first.
func (s *Service) Deliver(ctx context.Context, deviceID uuid.UUID) ([]protocol.Command, error) {
	now := s.Now()
	out := []protocol.Command{}
	err := s.Store.InTx(ctx, func(q *store.Queries) error {
		if _, err := q.ExpireCommands(ctx, now); err != nil {
			return err
		}
		pending, err := q.PendingCommands(ctx, deviceID)
		if err != nil {
			return err
		}
		var fresh []uuid.UUID
		for _, c := range pending {
			if c.Status == store.CommandQueued {
				fresh = append(fresh, c.ID)
			}
			out = append(out, protocol.Command{ID: c.ID.String(), Type: c.Type, Payload: json.RawMessage(c.Payload)})
		}
		return q.MarkCommandsDelivered(ctx, fresh, now)
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Start records that the device began a command. Repeat calls are accepted so
// a retrying agent is not punished.
func (s *Service) Start(ctx context.Context, deviceID, commandID uuid.UUID) error {
	now := s.Now()
	return s.Store.InTx(ctx, func(q *store.Queries) error {
		ok, err := q.MarkCommandRunning(ctx, store.DefaultTenantID, commandID, deviceID, now)
		if err != nil || ok {
			return err
		}
		c, err := q.GetCommand(ctx, store.DefaultTenantID, commandID)
		if errors.Is(err, store.ErrNotFound) || (err == nil && c.DeviceID != deviceID) {
			return fmt.Errorf("%w: %s", ErrNotFound, commandID)
		}
		return err
	})
}

// Complete stores a terminal result. Re-submitting a completed command's
// result succeeds without changing anything.
func (s *Service) Complete(ctx context.Context, deviceID, commandID uuid.UUID, r protocol.CommandResult) error {
	switch r.Status {
	case protocol.ResultSucceeded, protocol.ResultFailed, protocol.ResultTimedOut:
	default:
		return fmt.Errorf("%w: unsupported result status %q", ErrBadRequest, r.Status)
	}
	now := s.Now()
	stdout, stdoutTruncated := clampOutput(r.Stdout, r.StdoutTruncated)
	stderr, stderrTruncated := clampOutput(r.Stderr, r.StderrTruncated)
	errText, _ := clampOutput(r.Error, false)

	return s.Store.InTx(ctx, func(q *store.Queries) error {
		ok, err := q.CompleteCommand(ctx, store.DefaultTenantID, commandID, deviceID, r.Status, now)
		if err != nil {
			return err
		}
		if !ok {
			c, err := q.GetCommand(ctx, store.DefaultTenantID, commandID)
			if errors.Is(err, store.ErrNotFound) || (err == nil && c.DeviceID != deviceID) {
				return fmt.Errorf("%w: %s", ErrNotFound, commandID)
			}
			if err != nil {
				return err
			}
			return nil // already terminal: a duplicate submission
		}
		return q.InsertCommandResult(ctx, store.CommandResult{
			CommandID: commandID, ExitCode: r.ExitCode,
			Stdout: stdout, Stderr: stderr,
			StdoutTruncated: stdoutTruncated, StderrTruncated: stderrTruncated,
			Error: errText, StartedAt: r.StartedAt, FinishedAt: r.FinishedAt,
		})
	})
}

// Get returns a command and its result, if it has one.
func (s *Service) Get(ctx context.Context, commandID uuid.UUID) (store.Command, *store.CommandResult, error) {
	q := s.Store.Q()
	c, err := q.GetCommand(ctx, store.DefaultTenantID, commandID)
	if errors.Is(err, store.ErrNotFound) {
		return store.Command{}, nil, fmt.Errorf("%w: %s", ErrNotFound, commandID)
	}
	if err != nil {
		return store.Command{}, nil, err
	}
	r, err := q.GetCommandResult(ctx, store.DefaultTenantID, commandID)
	if errors.Is(err, store.ErrNotFound) {
		return c, nil, nil
	}
	if err != nil {
		return store.Command{}, nil, err
	}
	return c, &r, nil
}

// clampOutput makes agent output safe to store: no NUL bytes, valid UTF-8, and
// no longer than the cap.
func clampOutput(s string, truncated bool) (string, bool) {
	s = strings.ReplaceAll(s, "\x00", "")
	if len(s) > protocol.MaxOutputBytes {
		s = s[:protocol.MaxOutputBytes]
		truncated = true
	}
	return strings.ToValidUTF8(s, "�"), truncated
}
