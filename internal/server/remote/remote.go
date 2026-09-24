// Package remote runs remote sessions: an administrator's interactive
// PowerShell on a device, relayed through the server and recorded whole.
package remote

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"retune/internal/protocol"
	"retune/internal/server/store"
	"retune/internal/server/wake"
)

var (
	ErrNotFound        = errors.New("no such remote session")
	ErrEnded           = errors.New("the remote session has ended")
	ErrDeviceNotActive = errors.New("the device isn't active")
	ErrBadRequest      = errors.New("bad request")
)

// JoinTimeout is how long a device has to pick a session up.
const JoinTimeout = 10 * time.Minute

// Service starts and relays remote sessions.
type Service struct {
	Store *store.Store
	Wake  *wake.Hub
	Now   func() time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Start opens a session on a device, for a reason, and asks the device to
// join it.
func (s *Service) Start(ctx context.Context, deviceID uuid.UUID, actor, reason string) (store.RemoteSession, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" || len(reason) > 500 {
		return store.RemoteSession{}, fmt.Errorf("%w: a reason is required, at most 500 characters", ErrBadRequest)
	}
	now := s.now()
	r := store.RemoteSession{
		ID: uuid.Must(uuid.NewV7()), DeviceID: deviceID, StartedBy: actor, Reason: reason,
		Status: store.RemoteWaiting, CreatedAt: now,
	}
	err := s.Store.InTx(ctx, func(q *store.Queries) error {
		d, err := q.GetDevice(ctx, store.DefaultTenantID, deviceID)
		if errors.Is(err, store.ErrNotFound) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if d.Status != store.DeviceActive {
			return ErrDeviceNotActive
		}
		if err := q.CreateRemoteSession(ctx, r); err != nil {
			return err
		}
		payload, err := json.Marshal(protocol.RemoteShellPayload{SessionID: r.ID.String()})
		if err != nil {
			return err
		}
		if err := q.CreateCommand(ctx, store.Command{
			ID: uuid.Must(uuid.NewV7()), DeviceID: deviceID, Type: protocol.CommandRemoteShell, Payload: payload,
			Status: store.CommandQueued, CreatedBy: actor, CreatedAt: now, ExpiresAt: now.Add(JoinTimeout),
		}); err != nil {
			return err
		}
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: actor, Action: "remote_session.started", TargetKind: "device", TargetID: deviceID.String(),
			Details: map[string]any{"session_id": r.ID.String(), "hostname": d.Hostname, "reason": reason},
		})
	})
	return r, err
}

// current loads a session, ending it first if it has outlived its limits.
func (s *Service) current(ctx context.Context, id uuid.UUID) (store.RemoteSession, error) {
	q := s.Store.Q()
	r, err := q.GetRemoteSession(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return r, ErrNotFound
	} else if err != nil {
		return r, err
	}
	if r.Status == store.RemoteEnded {
		return r, nil
	}
	now := s.now()
	reason := ""
	switch {
	case r.Status == store.RemoteWaiting && now.Sub(r.CreatedAt) > JoinTimeout:
		reason = "the device didn't join within ten minutes"
	case r.StartedAt != nil && now.Sub(*r.StartedAt) > protocol.RemoteMaxDuration:
		reason = "the session reached its one-hour limit"
	case r.Status == store.RemoteActive:
		last, err := q.LastRemoteInput(ctx, id)
		if err != nil {
			return r, err
		}
		if now.Sub(last) > protocol.RemoteIdleTimeout {
			reason = "nothing was typed for fifteen minutes"
		}
	}
	if reason != "" {
		if _, err := q.EndRemoteSession(ctx, id, reason, now); err != nil {
			return r, err
		}
		return q.GetRemoteSession(ctx, id)
	}
	return r, nil
}

// Get is a session as it stands.
func (s *Service) Get(ctx context.Context, id uuid.UUID) (store.RemoteSession, error) {
	return s.current(ctx, id)
}

// Poll returns a session's chunks after seq, in the streams named (all when
// none), waiting up to wait for one to arrive or the session to end.
func (s *Service) Poll(ctx context.Context, id uuid.UUID, after int64, streams []string, wait time.Duration) (store.RemoteSession, []protocol.RemoteChunk, error) {
	r, err := s.current(ctx, id)
	if err != nil {
		return r, nil, err
	}
	q := s.Store.Q()
	chunks, err := q.RemoteChunks(ctx, id, after, streams, 500)
	if err != nil || len(chunks) > 0 || r.Status == store.RemoteEnded || wait <= 0 || s.Wake == nil {
		return r, chunks, err
	}
	ready := func() bool {
		more, err := q.RemoteChunks(ctx, id, after, streams, 1)
		if err != nil || len(more) > 0 {
			return true
		}
		cur, err := q.GetRemoteSession(ctx, id)
		return err != nil || cur.Status == store.RemoteEnded
	}
	s.Wake.Wait(ctx, wake.SessionKey(id.String()), wait, ready)
	if r, err = s.current(ctx, id); err != nil {
		return r, nil, err
	}
	chunks, err = q.RemoteChunks(ctx, id, after, streams, 500)
	return r, chunks, err
}

func checkChunk(data string) error {
	if data == "" || len(data) > protocol.MaxRemoteChunk || !utf8.ValidString(data) {
		return fmt.Errorf("%w: data must be 1 to %d bytes of text", ErrBadRequest, protocol.MaxRemoteChunk)
	}
	return nil
}

// Input is something an administrator typed.
func (s *Service) Input(ctx context.Context, id uuid.UUID, data string) error {
	if err := checkChunk(data); err != nil {
		return err
	}
	r, err := s.current(ctx, id)
	if err != nil {
		return err
	}
	if r.Status == store.RemoteEnded {
		return ErrEnded
	}
	return s.Store.Q().AppendRemoteChunk(ctx, id, protocol.RemoteStreamIn, data, s.now())
}

// Output is something the shell wrote, sent by the device the session is on.
func (s *Service) Output(ctx context.Context, deviceID, id uuid.UUID, stream, data string) error {
	if stream != protocol.RemoteStreamOut && stream != protocol.RemoteStreamErr {
		return fmt.Errorf("%w: stream must be out or err", ErrBadRequest)
	}
	if err := checkChunk(data); err != nil {
		return err
	}
	r, err := s.onDevice(ctx, deviceID, id)
	if err != nil {
		return err
	}
	if r.Status == store.RemoteEnded {
		return ErrEnded
	}
	q := s.Store.Q()
	if err := q.MarkRemoteSessionActive(ctx, id, s.now()); err != nil {
		return err
	}
	return q.AppendRemoteChunk(ctx, id, stream, data, s.now())
}

// Join marks a session active, when its device has started the shell.
func (s *Service) Join(ctx context.Context, deviceID, id uuid.UUID) error {
	r, err := s.onDevice(ctx, deviceID, id)
	if err != nil {
		return err
	}
	if r.Status == store.RemoteEnded {
		return ErrEnded
	}
	return s.Store.Q().MarkRemoteSessionActive(ctx, id, s.now())
}

// onDevice loads a session, as not found unless it is on this device.
func (s *Service) onDevice(ctx context.Context, deviceID, id uuid.UUID) (store.RemoteSession, error) {
	r, err := s.current(ctx, id)
	if err == nil && r.DeviceID != deviceID {
		return r, ErrNotFound
	}
	return r, err
}

// DeviceEnd ends a session from the device's side: the shell exited, or it
// was told the session was over.
func (s *Service) DeviceEnd(ctx context.Context, deviceID, id uuid.UUID, reason string) error {
	if _, err := s.onDevice(ctx, deviceID, id); err != nil {
		return err
	}
	if len(reason) > 500 {
		reason = reason[:500]
	}
	_, err := s.Store.Q().EndRemoteSession(ctx, id, "device: "+reason, s.now())
	return err
}

// End ends a session from the console.
func (s *Service) End(ctx context.Context, id uuid.UUID, actor string) error {
	r, err := s.current(ctx, id)
	if err != nil {
		return err
	}
	return s.Store.InTx(ctx, func(q *store.Queries) error {
		ended, err := q.EndRemoteSession(ctx, id, "ended by "+actor, s.now())
		if err != nil || !ended {
			return err
		}
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: actor, Action: "remote_session.ended", TargetKind: "device", TargetID: r.DeviceID.String(),
			Details: map[string]any{"session_id": id.String()},
		})
	})
}
