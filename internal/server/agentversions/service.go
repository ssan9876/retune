// Package agentversions manages uploaded agent builds: the metadata row in
// Postgres and the bytes on disk that it describes.
package agentversions

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"

	"retune/internal/protocol"
	"retune/internal/server/artifacts"
	"retune/internal/server/store"
)

var (
	// ErrNotFound is returned when a build does not exist.
	ErrNotFound = errors.New("agent version not found")
	// ErrVersionTaken is returned when a version string is already in use.
	ErrVersionTaken = errors.New("that version has already been uploaded")
	// ErrBadRequest is returned for input the caller can fix.
	ErrBadRequest = errors.New("bad request")
)

// MaxUploadBytes caps one uploaded build. The agent is a single static Go
// binary of a few megabytes; a hundred times that is a mistake or an attack,
// not a release.
const MaxUploadBytes = 128 << 20

// Service owns agent builds: their metadata and the bytes it describes.
type Service struct {
	Store     *store.Store
	Artifacts artifacts.Store
	Now       func() time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// NewVersion describes a build to upload.
type NewVersion struct {
	Version string
	Notes   string
	Actor   string
}

// Upload stores a build and records what was received. The bytes land first:
// a metadata row describing a file that does not exist is a state an agent
// cannot recover from, whereas an orphaned file is merely wasted disk.
func (s *Service) Upload(ctx context.Context, in NewVersion, body io.Reader) (store.AgentVersion, error) {
	version := strings.TrimSpace(in.Version)
	if version == "" {
		return store.AgentVersion{}, fmt.Errorf("%w: a build needs a version", ErrBadRequest)
	}
	if _, err := s.Store.Q().GetAgentVersionByVersion(ctx, version); err == nil {
		return store.AgentVersion{}, ErrVersionTaken
	} else if !errors.Is(err, store.ErrNotFound) {
		return store.AgentVersion{}, err
	}

	sum, size, err := s.Artifacts.Put(version, body, MaxUploadBytes)
	if errors.Is(err, artifacts.ErrExists) {
		return store.AgentVersion{}, ErrVersionTaken
	}
	if err != nil {
		// A bad version string is the caller's to fix, and Put is what knows
		// which strings are usable as a directory name.
		return store.AgentVersion{}, fmt.Errorf("%w: %v", ErrBadRequest, err)
	}

	v := store.AgentVersion{
		ID: uuid.Must(uuid.NewV7()), Version: version, SHA256: sum, SizeBytes: size,
		Notes: in.Notes, CreatedAt: s.now(), CreatedBy: in.Actor,
	}
	err = s.Store.InTx(ctx, func(q *store.Queries) error {
		if err := q.CreateAgentVersion(ctx, v); err != nil {
			return err
		}
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: in.Actor, Action: "agent_version.uploaded", TargetKind: "agent_version",
			TargetID: v.ID.String(),
			Details:  map[string]any{"version": version, "sha256": sum, "size_bytes": size},
		})
	})
	if err != nil {
		// The row failed after the bytes landed; leaving them behind would be
		// an artifact with no metadata pointing at it, indistinguishable from
		// a completed upload once someone looks at the disk.
		_ = s.Artifacts.Remove(version)
		return store.AgentVersion{}, err
	}
	return v, nil
}

// Get looks up a build by id.
func (s *Service) Get(ctx context.Context, id uuid.UUID) (store.AgentVersion, error) {
	v, err := s.Store.Q().GetAgentVersion(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return store.AgentVersion{}, ErrNotFound
	}
	return v, err
}

// List returns one page of uploaded builds, newest first.
func (s *Service) List(ctx context.Context, page store.Page) ([]store.AgentVersion, int, error) {
	return s.Store.Q().ListAgentVersions(ctx, page)
}

// Delete removes a build's metadata and any assignments referencing it, then
// its bytes. The bytes go last: if the transaction fails, a build that is
// still referenced by a row must not lose the file it points to.
func (s *Service) Delete(ctx context.Context, id uuid.UUID, actor string) error {
	var v store.AgentVersion
	err := s.Store.InTx(ctx, func(q *store.Queries) error {
		var err error
		v, err = q.GetAgentVersion(ctx, id)
		if errors.Is(err, store.ErrNotFound) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if err := q.DeleteAssignmentsForItem(ctx, protocol.ItemKindAgent, id); err != nil {
			return err
		}
		if err := q.DeleteAgentVersion(ctx, id); err != nil {
			return err
		}
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: actor, Action: "agent_version.deleted", TargetKind: "agent_version", TargetID: id.String(),
			Details: map[string]any{"version": v.Version},
		})
	})
	if err != nil {
		return err
	}
	return s.Artifacts.Remove(v.Version)
}

// Open streams a build's bytes for download.
func (s *Service) Open(ctx context.Context, id uuid.UUID) (io.ReadCloser, int64, error) {
	v, err := s.Get(ctx, id)
	if err != nil {
		return nil, 0, err
	}
	return s.Artifacts.Open(v.Version)
}

// RecordResult stores the outcome of one device's attempt to install this
// build. There is no history table here: unlike a script run or an app
// install, an agent either is or is not on a given build, so the latest
// status plus the reported version says everything there is to say.
func (s *Service) RecordResult(ctx context.Context, deviceID, id uuid.UUID, r protocol.AgentUpdateResult) error {
	switch r.Status {
	case protocol.ResultSucceeded, protocol.ResultFailed:
	default:
		return fmt.Errorf("%w: unsupported update status %q", ErrBadRequest, r.Status)
	}

	status := store.ItemSucceeded
	if r.Status != protocol.ResultSucceeded {
		status = store.ItemFailed
	}
	detail := r.Detail
	if detail == "" && r.RolledBackFrom != "" {
		// A rollback with nothing else to say is still worth naming: this is
		// what lets the console report "rolled back from 0.2.0" instead of
		// leaving the administrator to guess why a device is back on an old
		// build.
		detail = fmt.Sprintf("rolled back from %s to %s", r.RolledBackFrom, r.Version)
	}

	// ReportedAt is when the agent observed the outcome, which predates
	// whenever this request happens to arrive at the server. Fall back to
	// now only for a caller that left it unset.
	updatedAt := r.ReportedAt
	if updatedAt.IsZero() {
		updatedAt = s.now()
	}

	return s.Store.Q().SetItemStatus(ctx, store.ItemStatus{
		DeviceID: deviceID, ItemKind: protocol.ItemKindAgent, ItemID: id,
		Status: status, Detail: detail,
		// Agent builds are identified by a version string, not the integer
		// version this field was built for, so it is left at its zero value.
		Version:   0,
		UpdatedAt: updatedAt,
	})
}
