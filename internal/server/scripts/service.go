package scripts

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"retune/internal/protocol"
	"retune/internal/server/store"
)

var (
	// ErrNotFound is returned when a script or version does not exist.
	ErrNotFound = errors.New("script not found")
	// ErrNameTaken is returned when a script name is already in use.
	ErrNameTaken = errors.New("a script with that name already exists")
	// ErrBadRequest is returned for input the caller can fix.
	ErrBadRequest = errors.New("bad request")
)

// MaxBodyBytes caps one script body. PowerShell that long is a program, and
// belongs in a package rather than a deployment.
const MaxBodyBytes = 256 << 10

// Service owns the script library.
type Service struct {
	Store *store.Store
	Now   func() time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// NewScript describes a script to create or update.
type NewScript struct {
	Name          string
	Description   string
	Body          string
	DetectionBody string
	Actor         string
}

// Hash identifies a version's contents, the way inventory documents are
// hashed.
func Hash(body, detection string) string {
	sum := sha256.Sum256([]byte(body + "\x00" + detection))
	return hex.EncodeToString(sum[:])
}

func (in NewScript) validate() error {
	if strings.TrimSpace(in.Name) == "" {
		return fmt.Errorf("%w: a script needs a name", ErrBadRequest)
	}
	if strings.TrimSpace(in.Body) == "" {
		return fmt.Errorf("%w: a script needs a body", ErrBadRequest)
	}
	if len(in.Body) > MaxBodyBytes || len(in.DetectionBody) > MaxBodyBytes {
		return fmt.Errorf("%w: a script body may be at most %d bytes", ErrBadRequest, MaxBodyBytes)
	}
	return nil
}

// Create adds a script and its first version.
func (s *Service) Create(ctx context.Context, in NewScript) (store.Script, error) {
	if err := in.validate(); err != nil {
		return store.Script{}, err
	}
	now := s.now()
	sc := store.Script{
		ID: uuid.Must(uuid.NewV7()), Name: strings.TrimSpace(in.Name), Description: in.Description,
		CurrentVersion: 1, CreatedAt: now, UpdatedAt: now, CreatedBy: in.Actor,
	}
	err := s.Store.InTx(ctx, func(q *store.Queries) error {
		if _, err := q.GetScriptByName(ctx, sc.Name); err == nil {
			return ErrNameTaken
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}
		if err := q.CreateScript(ctx, sc); err != nil {
			return err
		}
		if err := q.CreateScriptVersion(ctx, store.ScriptVersion{
			ScriptID: sc.ID, Version: 1, Body: in.Body, DetectionBody: in.DetectionBody,
			Hash: Hash(in.Body, in.DetectionBody), CreatedAt: now, CreatedBy: in.Actor,
		}); err != nil {
			return err
		}
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: in.Actor, Action: "script.created", TargetKind: "script", TargetID: sc.ID.String(),
			Details: map[string]any{"name": sc.Name},
		})
	})
	if err != nil {
		return store.Script{}, err
	}
	return sc, nil
}

// Update changes a script. A new version is written only when the body or the
// detection script actually changed, so renaming does not make every device
// run it again.
func (s *Service) Update(ctx context.Context, id uuid.UUID, in NewScript) (store.Script, error) {
	if err := in.validate(); err != nil {
		return store.Script{}, err
	}
	now := s.now()
	var out store.Script
	err := s.Store.InTx(ctx, func(q *store.Queries) error {
		sc, err := q.GetScript(ctx, store.DefaultTenantID, id)
		if errors.Is(err, store.ErrNotFound) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		name := strings.TrimSpace(in.Name)
		if other, err := q.GetScriptByName(ctx, name); err == nil && other.ID != id {
			return ErrNameTaken
		} else if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}

		current, err := q.GetScriptVersion(ctx, store.DefaultTenantID, id, sc.CurrentVersion)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		newVersion := current.Body != in.Body || current.DetectionBody != in.DetectionBody
		if newVersion {
			sc.CurrentVersion++
			if err := q.CreateScriptVersion(ctx, store.ScriptVersion{
				ScriptID: id, Version: sc.CurrentVersion, Body: in.Body, DetectionBody: in.DetectionBody,
				Hash: Hash(in.Body, in.DetectionBody), CreatedAt: now, CreatedBy: in.Actor,
			}); err != nil {
				return err
			}
		}
		sc.Name, sc.Description, sc.UpdatedAt = name, in.Description, now
		if err := q.UpdateScript(ctx, store.DefaultTenantID, sc); err != nil {
			return err
		}
		out = sc
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: in.Actor, Action: "script.updated", TargetKind: "script", TargetID: id.String(),
			Details: map[string]any{"name": sc.Name, "new_version": newVersion, "version": sc.CurrentVersion},
		})
	})
	if err != nil {
		return store.Script{}, err
	}
	return out, nil
}

// Delete removes a script, its versions and its assignments. Runs are kept.
func (s *Service) Delete(ctx context.Context, id uuid.UUID, actor string) error {
	return s.Store.InTx(ctx, func(q *store.Queries) error {
		sc, err := q.GetScript(ctx, store.DefaultTenantID, id)
		if errors.Is(err, store.ErrNotFound) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if err := q.DeleteAssignmentsForItem(ctx, protocol.ItemKindScript, id); err != nil {
			return err
		}
		if err := q.DeleteScript(ctx, store.DefaultTenantID, id); err != nil {
			return err
		}
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: actor, Action: "script.deleted", TargetKind: "script", TargetID: id.String(),
			Details: map[string]any{"name": sc.Name},
		})
	})
}

func (s *Service) Get(ctx context.Context, id uuid.UUID) (store.Script, error) {
	sc, err := s.Store.Q().GetScript(ctx, store.DefaultTenantID, id)
	if errors.Is(err, store.ErrNotFound) {
		return store.Script{}, ErrNotFound
	}
	return sc, err
}

func (s *Service) List(ctx context.Context, page store.Page) ([]store.Script, int, error) {
	return s.Store.Q().ListScripts(ctx, page)
}

func (s *Service) Version(ctx context.Context, id uuid.UUID, version int) (store.ScriptVersion, error) {
	v, err := s.Store.Q().GetScriptVersion(ctx, store.DefaultTenantID, id, version)
	if errors.Is(err, store.ErrNotFound) {
		return store.ScriptVersion{}, ErrNotFound
	}
	return v, err
}

func (s *Service) ListVersions(ctx context.Context, id uuid.UUID) ([]store.ScriptVersion, error) {
	return s.Store.Q().ListScriptVersions(ctx, id)
}

// RecordRun stores one reported run and updates the device's status for that
// script, both in one transaction so the summary can never disagree with the
// history.
func (s *Service) RecordRun(ctx context.Context, deviceID, scriptID uuid.UUID, r protocol.ScriptRun) error {
	switch r.Status {
	case protocol.ResultSucceeded, protocol.ResultFailed, protocol.ResultTimedOut:
	default:
		return fmt.Errorf("%w: unsupported run status %q", ErrBadRequest, r.Status)
	}
	switch r.Phase {
	case protocol.PhaseScript, protocol.PhaseDetection, protocol.PhaseRemediation:
	default:
		return fmt.Errorf("%w: unsupported phase %q", ErrBadRequest, r.Phase)
	}

	now := s.now()
	stdout, stdoutTruncated := clamp(r.Stdout, r.StdoutTruncated)
	stderr, stderrTruncated := clamp(r.Stderr, r.StderrTruncated)
	errText, _ := clamp(r.Error, false)

	status := store.ItemSucceeded
	if r.Status != protocol.ResultSucceeded {
		status = store.ItemFailed
	}
	detail := ""
	switch {
	case errText != "":
		detail = errText
	case r.Status != protocol.ResultSucceeded:
		detail = fmt.Sprintf("%s exited %d", r.Phase, r.ExitCode)
	case r.Remediated:
		detail = "remediated"
	}

	return s.Store.InTx(ctx, func(q *store.Queries) error {
		if err := q.InsertScriptRun(ctx, store.ScriptRun{
			ID: uuid.Must(uuid.NewV7()), ScriptID: scriptID, Version: r.Version, DeviceID: deviceID,
			Status: r.Status, Phase: r.Phase, Remediated: r.Remediated, ExitCode: r.ExitCode,
			Stdout: stdout, Stderr: stderr,
			StdoutTruncated: stdoutTruncated, StderrTruncated: stderrTruncated,
			Error: errText, StartedAt: r.StartedAt, FinishedAt: r.FinishedAt,
		}); err != nil {
			return err
		}
		return q.SetItemStatus(ctx, store.ItemStatus{
			DeviceID: deviceID, ItemKind: protocol.ItemKindScript, ItemID: scriptID,
			Status: status, Detail: detail, Version: r.Version, UpdatedAt: now,
		})
	})
}

// SetItemPending records that a deployment applies to a device but has not run,
// which is how a script set to run as the signed-in user reports itself.
func (s *Service) SetItemPending(ctx context.Context, deviceID, scriptID uuid.UUID, version int, reason string) error {
	return s.Store.Q().SetItemStatus(ctx, store.ItemStatus{
		DeviceID: deviceID, ItemKind: protocol.ItemKindScript, ItemID: scriptID,
		Status: store.ItemPending, Detail: reason, Version: version, UpdatedAt: s.now(),
	})
}

// clamp makes agent output safe to store: no NUL bytes, valid UTF-8, and no
// longer than the cap.
func clamp(s string, truncated bool) (string, bool) {
	s = strings.ReplaceAll(s, "\x00", "")
	if len(s) > protocol.MaxOutputBytes {
		s = s[:protocol.MaxOutputBytes]
		truncated = true
	}
	return strings.ToValidUTF8(s, "�"), truncated
}
