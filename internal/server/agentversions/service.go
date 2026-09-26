// Package agentversions manages uploaded agent builds: the metadata row in
// Postgres and the bytes on disk that it describes.
package agentversions

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"retune/internal/protocol"
	"retune/internal/release"
	"retune/internal/server/artifacts"
	"retune/internal/server/store"
)

var (
	// ErrNotFound is returned when a build does not exist.
	ErrNotFound = errors.New("agent version not found")
	// ErrVersionTaken is returned when a version already has a build for the
	// platform being uploaded.
	ErrVersionTaken = errors.New("that version has already been uploaded")
	// ErrNoBuild is returned when a version has no build a device can run.
	ErrNoBuild = errors.New("no build of this version for this platform")
	// ErrBadRequest is returned for input the caller can fix.
	ErrBadRequest = errors.New("bad request")
	// ErrNoReleaseKeys means the service has no release keys configured, so no
	// upload can ever be verified.
	ErrNoReleaseKeys = errors.New("no release keys are configured")
)

// MaxUploadBytes caps one uploaded build. The agent is a single static Go
// binary of a few megabytes; a hundred times that is a mistake or an attack,
// not a release.
const MaxUploadBytes = 128 << 20

// MaxNotesLength caps a build's release notes, in characters. Notes are shown
// on the console's list of builds; anything longer belongs in a changelog.
const MaxNotesLength = 2000

// SignatureHeader carries the build's release signature: the base64 of its
// .sig sidecar. It is defined here, not in adminapi, because the service is
// what needs the header's name in its own rejection messages, and it must
// not import the handler package to get it. adminapi.SignatureHeader is the
// same constant, re-exported for the handler and for tests.
const SignatureHeader = "X-Retune-Signature"

// Service owns agent builds: their metadata and the bytes it describes.
type Service struct {
	Store     *store.Store
	Artifacts artifacts.Store
	Now       func() time.Time
	// ReleaseKeys are the public keys a build must be signed by. With none
	// configured every upload is refused: nothing silently accepts.
	ReleaseKeys []release.PublicKey
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// NewVersion describes a build to upload. SignatureHeader is the raw header
// value the caller sent: empty when the header was absent at all. Decoding it
// into a release.Signature happens inside Upload, not in the handler, because
// every way that decoding can fail is itself a rejection that must be
// audited, and the handler has no access to the audit log.
type NewVersion struct {
	Version string
	// Platform is the build's GOOS-GOARCH (protocol.Platforms). Empty means
	// windows-amd64, which is what every upload was before platforms existed.
	Platform        string
	Notes           string
	Actor           string
	SignatureHeader string
}

// Upload stores one platform's build of a version and records what was
// received. The first build of a version creates it; a build for another
// platform joins it, so one assignment reaches every kind of machine. The
// bytes land first: a metadata row describing a file that does not exist is a
// state an agent cannot recover from, whereas an orphaned file is merely
// wasted disk.
func (s *Service) Upload(ctx context.Context, in NewVersion, body io.Reader) (store.AgentVersion, error) {
	version := strings.TrimSpace(in.Version)
	if version == "" {
		return store.AgentVersion{}, s.reject(ctx, in, ErrBadRequest, "a build needs a version")
	}
	platform := strings.TrimSpace(in.Platform)
	if platform == "" {
		platform = protocol.PlatformWindowsAMD64
	}
	in.Platform = platform
	if !protocol.ValidPlatform(platform) {
		return store.AgentVersion{}, s.reject(ctx, in, ErrBadRequest, fmt.Sprintf(
			"%q is not a platform; use one of %s", platform, strings.Join(protocol.Platforms, ", ")))
	}
	if utf8.RuneCountInString(in.Notes) > MaxNotesLength {
		return store.AgentVersion{}, s.reject(ctx, in, ErrBadRequest,
			fmt.Sprintf("notes may be at most %d characters", MaxNotesLength))
	}
	existing, err := s.Store.Q().GetAgentVersionByVersion(ctx, version)
	switch {
	case err == nil:
		if _, err := s.Store.Q().GetAgentVersionBuild(ctx, existing.ID, platform); err == nil {
			return store.AgentVersion{}, s.reject(ctx, in, ErrVersionTaken,
				fmt.Sprintf("a %s build of this version already exists", platform))
		} else if !errors.Is(err, store.ErrNotFound) {
			return store.AgentVersion{}, err
		}
	case errors.Is(err, store.ErrNotFound):
		existing = store.AgentVersion{}
	default:
		return store.AgentVersion{}, err
	}

	if len(s.ReleaseKeys) == 0 {
		return store.AgentVersion{}, s.reject(ctx, in, ErrNoReleaseKeys, "no release keys are configured to verify against")
	}

	// Everything the caller sent about its signature is decoded here, inside
	// the audited path: a missing header, one that is not base64, or one
	// whose bytes are not a sidecar is exactly as much a probe worth noticing
	// as a signature that fails to verify.
	if in.SignatureHeader == "" {
		return store.AgentVersion{}, s.reject(ctx, in, ErrBadRequest,
			"the upload carried no "+SignatureHeader+" header")
	}
	raw, err := base64.StdEncoding.DecodeString(in.SignatureHeader)
	if err != nil {
		return store.AgentVersion{}, s.reject(ctx, in, ErrBadRequest, SignatureHeader+" is not base64")
	}
	sig, err := release.DecodeSidecar(raw)
	if err != nil {
		return store.AgentVersion{}, s.reject(ctx, in, ErrBadRequest, SignatureHeader+": "+err.Error())
	}

	keyKnown := false
	for _, k := range s.ReleaseKeys {
		if k.ID() == sig.KeyID {
			keyKnown = true
			break
		}
	}
	if !keyKnown {
		return store.AgentVersion{}, s.rejectSig(ctx, in, sig, ErrBadRequest, fmt.Sprintf(
			"the signature names key %s, which is not a configured release key", sig.KeyID))
	}

	sum, size, err := s.Artifacts.PutBuild(version, platform, body, MaxUploadBytes)
	switch {
	case errors.Is(err, artifacts.ErrExists):
		// The pre-check above is racy against a concurrent upload of the
		// same version: both can pass it before either writes bytes. Put's
		// ErrExists is what actually catches that, and the collision is
		// exactly as worth noticing as the ordinary duplicate rejected above.
		return store.AgentVersion{}, s.reject(ctx, in, ErrVersionTaken, "that version has already been uploaded")
	case errors.Is(err, artifacts.ErrBadVersion):
		// A bad version string is the caller's to fix, and Put is what knows
		// which strings are usable as a directory name.
		return store.AgentVersion{}, s.reject(ctx, in, ErrBadRequest, err.Error())
	case err != nil:
		// Anything else -- disk full, permission denied -- is a server fault,
		// not something the caller can fix by resubmitting, so it stays an
		// internal error rather than a 400.
		return store.AgentVersion{}, err
	}

	// The bytes are on disk; from here every refusal removes them. The checks
	// run in the order that gives the most useful message: a wrong file, a
	// wrong version, then a signature that is simply forged.
	if !strings.EqualFold(sum, sig.SHA256) {
		_ = s.Artifacts.RemoveBuild(version, platform)
		return store.AgentVersion{}, s.rejectSig(ctx, in, sig, ErrBadRequest, fmt.Sprintf(
			"the uploaded bytes hash to %s but the signature is over %s", sum, sig.SHA256))
	}
	if version != sig.Version {
		_ = s.Artifacts.RemoveBuild(version, platform)
		return store.AgentVersion{}, s.rejectSig(ctx, in, sig, ErrBadRequest, fmt.Sprintf(
			"declared version %q does not match the signed version %q", version, sig.Version))
	}
	if err := release.Verify(s.ReleaseKeys, release.Manifest{Version: version, SHA256: sum}, sig); err != nil {
		_ = s.Artifacts.RemoveBuild(version, platform)
		return store.AgentVersion{}, s.rejectSig(ctx, in, sig, ErrBadRequest, "the signature did not verify")
	}

	// A new version's own row describes its first build, as it always has:
	// anything that reads a version without asking for a platform still sees
	// a real build.
	v := existing
	if v.ID == uuid.Nil {
		v = store.AgentVersion{
			ID: uuid.Must(uuid.NewV7()), Version: version, SHA256: sum, SizeBytes: size,
			Notes: in.Notes, CreatedAt: s.now(), CreatedBy: in.Actor,
			KeyID: sig.KeyID, Signature: base64.StdEncoding.EncodeToString(sig.Signature),
		}
	}
	build := store.AgentVersionBuild{
		AgentVersionID: v.ID, Platform: platform, SHA256: sum, SizeBytes: size,
		KeyID: sig.KeyID, Signature: base64.StdEncoding.EncodeToString(sig.Signature),
		CreatedAt: s.now(), CreatedBy: in.Actor,
	}
	err = s.Store.InTx(ctx, func(q *store.Queries) error {
		if existing.ID == uuid.Nil {
			if err := q.CreateAgentVersion(ctx, v); err != nil {
				return err
			}
		}
		if err := q.CreateAgentVersionBuild(ctx, build); err != nil {
			return err
		}
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: in.Actor, Action: "agent_version.uploaded", TargetKind: "agent_version",
			TargetID: v.ID.String(),
			Details: map[string]any{"version": version, "platform": platform, "sha256": sum,
				"size_bytes": size, "key_id": sig.KeyID},
		})
	})
	if err != nil {
		// The row failed after the bytes landed; leaving them behind would be
		// an artifact with no metadata pointing at it, indistinguishable from
		// a completed upload once someone looks at the disk.
		_ = s.Artifacts.RemoveBuild(version, platform)
		mapped := uploadError(err)
		if errors.Is(mapped, ErrVersionTaken) {
			// Same race as the Artifacts.Put case above, caught here instead
			// because the unique index is what actually serialises two
			// concurrent uploads through the pre-check at the same instant.
			return store.AgentVersion{}, s.reject(ctx, in, ErrVersionTaken, "that version has already been uploaded")
		}
		// Every other transaction failure is a server fault, not the
		// caller's to fix, and stays an unaudited internal error.
		return store.AgentVersion{}, mapped
	}
	return v, nil
}

// reject records why an upload was refused and returns sentinel, wrapped with
// reason, as the error the caller sees. The audit entry is the point: an
// admin account pushing a build the release key never signed -- or probing
// the endpoint with no signature at all -- is exactly what this milestone
// exists to notice, and a 400 alone leaves no trace of it. key_id is empty
// here: it is only known once a signature has been decoded, and every path
// that reaches this far never got that far.
func (s *Service) reject(ctx context.Context, in NewVersion, sentinel error, reason string) error {
	return s.rejectKey(ctx, in, "", sentinel, reason)
}

// rejectSig is reject for a failure discovered after the signature was
// successfully decoded, so the audit entry can name the key it claimed.
func (s *Service) rejectSig(ctx context.Context, in NewVersion, sig release.Signature, sentinel error, reason string) error {
	return s.rejectKey(ctx, in, sig.KeyID, sentinel, reason)
}

func (s *Service) rejectKey(ctx context.Context, in NewVersion, keyID string, sentinel error, reason string) error {
	if err := s.Store.Q().InsertAudit(ctx, store.AuditEntry{
		Actor: in.Actor, Action: "agent_version.rejected", TargetKind: "agent_version", TargetID: "",
		Details: map[string]any{"version": in.Version, "platform": in.Platform, "reason": reason, "key_id": keyID},
	}); err != nil {
		// The refusal stands either way; losing the audit row is the lesser
		// failure, but not a silent one.
		return fmt.Errorf("%w: %s (and recording the refusal failed: %v)", sentinel, reason, err)
	}
	return fmt.Errorf("%w: %s", sentinel, reason)
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
	v, err := s.Store.Q().GetAgentVersion(ctx, store.DefaultTenantID, id)
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
		v, err = q.GetAgentVersion(ctx, store.DefaultTenantID, id)
		if errors.Is(err, store.ErrNotFound) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if err := q.DeleteAssignmentsForItem(ctx, protocol.ItemKindAgent, id); err != nil {
			return err
		}
		if err := q.DeleteAgentVersion(ctx, store.DefaultTenantID, id); err != nil {
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

// Builds returns the builds of each of the given versions.
func (s *Service) Builds(ctx context.Context, ids []uuid.UUID) (map[uuid.UUID][]store.AgentVersionBuild, error) {
	return s.Store.Q().ListAgentVersionBuilds(ctx, ids)
}

// BuildFor returns a version and the build of it that a device of platform
// can run: its own platform's, or for a Mac a universal build. ErrNoBuild
// means the version exists but has nothing this device can run.
func (s *Service) BuildFor(ctx context.Context, id uuid.UUID, platform string) (store.AgentVersion, store.AgentVersionBuild, error) {
	v, err := s.Get(ctx, id)
	if err != nil {
		return store.AgentVersion{}, store.AgentVersionBuild{}, err
	}
	for _, p := range protocol.BuildCandidates(platform) {
		b, err := s.Store.Q().GetAgentVersionBuild(ctx, id, p)
		if err == nil {
			return v, b, nil
		}
		if !errors.Is(err, store.ErrNotFound) {
			return store.AgentVersion{}, store.AgentVersionBuild{}, err
		}
	}
	return v, store.AgentVersionBuild{}, ErrNoBuild
}

// Open streams a version's windows-amd64 build, the only platform there was
// before builds had one.
func (s *Service) Open(ctx context.Context, id uuid.UUID) (io.ReadCloser, int64, error) {
	return s.OpenBuild(ctx, id, protocol.PlatformWindowsAMD64)
}

// OpenBuild streams the bytes of the build BuildFor chooses.
func (s *Service) OpenBuild(ctx context.Context, id uuid.UUID, platform string) (io.ReadCloser, int64, error) {
	v, b, err := s.BuildFor(ctx, id, platform)
	if err != nil {
		return nil, 0, err
	}
	return s.Artifacts.OpenBuild(v.Version, b.Platform)
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
