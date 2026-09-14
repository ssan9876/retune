// Package agentversions manages uploaded agent builds: the metadata row in
// Postgres and the bytes on disk that it describes.
package agentversions

import (
	"bytes"
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

	// A build whose version was never stamped in reports the placeholder for
	// ever, and the agent refuses to install one, so accepting it would only
	// produce a build that can be assigned to a whole fleet and can never
	// succeed anywhere. This is the last moment there is somebody at a console
	// to tell about it. The scan is for the declared version and nothing else:
	// the placeholder string is in every binary's rodata whether the stamp
	// happened or not, so its presence proves nothing either way.
	stamped, err := s.stampedWith(version)
	if err != nil {
		_ = s.Artifacts.Remove(version)
		return store.AgentVersion{}, err
	}
	if !stamped {
		_ = s.Artifacts.Remove(version)
		return store.AgentVersion{}, fmt.Errorf(
			"%w: the uploaded binary does not contain version %q; was it built with the version stamp?",
			ErrBadRequest, version)
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
		return store.AgentVersion{}, uploadError(err)
	}
	return v, nil
}

// scanChunk is how much of a stored build is held in memory at a time while
// looking for the version string. The cap on an upload is 128 MiB and a
// server may be handling several at once, so the file is read in pieces
// rather than whole.
const scanChunk = 1 << 20

// stampedWith reports whether the stored bytes for version contain that
// version string anywhere.
func (s *Service) stampedWith(version string) (bool, error) {
	r, _, err := s.Artifacts.Open(version)
	if err != nil {
		return false, err
	}
	defer r.Close()
	return containsVersion(r, version)
}

// containsVersion streams r looking for version. Each chunk keeps the last
// len(version)-1 bytes of the one before it, so a match that straddles the
// boundary between two reads is still found -- otherwise a perfectly well
// stamped build would be rejected depending on where its version happened to
// land in the file.
func containsVersion(r io.Reader, version string) (bool, error) {
	needle := []byte(version)
	if len(needle) == 0 || len(needle) > scanChunk {
		return false, nil
	}
	buf := make([]byte, scanChunk)
	carried := 0
	for {
		n, err := io.ReadFull(r, buf[carried:])
		have := carried + n
		if bytes.Contains(buf[:have], needle) {
			return true, nil
		}
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return false, nil
			}
			return false, err
		}
		// Carry the tail forward: a match can be at most len(needle)-1 bytes
		// into the next chunk before it is wholly inside it.
		carried = len(needle) - 1
		copy(buf, buf[have-carried:have])
	}
}

// uploadError translates what CreateAgentVersion's transaction can fail with
// into what a caller of Upload should see. The pre-check above is racy
// against a concurrent upload of the same version: both can pass it before
// either writes a row. The unique index is what actually catches that, and
// its violation must read like the pre-check's, not like an internal error.
func uploadError(err error) error {
	if errors.Is(err, store.ErrDuplicate) {
		return ErrVersionTaken
	}
	return err
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

	// UpdatedAt is server time, not r.ReportedAt: endpoint clocks skew, and
	// this column means "when did the server learn this", same as apps and
	// scripts. ReportedAt still travels on the wire for the agent's own log.
	return s.Store.Q().SetItemStatus(ctx, store.ItemStatus{
		DeviceID: deviceID, ItemKind: protocol.ItemKindAgent, ItemID: id,
		Status: status, Detail: detail,
		// An agent build is immutable, so its item version is always 1 - the
		// same version check-in offers the device - never the integer this
		// field would carry for a script or app that can change under one id.
		Version:   1,
		UpdatedAt: s.now(),
	})
}
