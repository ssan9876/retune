package apps

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
	// ErrNotFound is returned when an app or version does not exist.
	ErrNotFound = errors.New("app not found")
	// ErrNameTaken is returned when an app name is already in use.
	ErrNameTaken = errors.New("an app with that name already exists")
	// ErrBadRequest is returned for input the caller can fix.
	ErrBadRequest = errors.New("bad request")
)

// Service owns the app library.
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

// NewApp describes an app to create or update.
type NewApp struct {
	Name          string
	Description   string
	PackageID     string
	PinnedVersion string
	Scope         string
	InstallArgs   string
	Actor         string
}

// Hash identifies a version's definition. Name and description are not part of
// it: renaming an app is not a reason to install it again.
func Hash(packageID, pinned, scope, args string) string {
	sum := sha256.Sum256([]byte(packageID + "\x00" + pinned + "\x00" + scope + "\x00" + args))
	return hex.EncodeToString(sum[:])
}

func (in NewApp) validate() error {
	if strings.TrimSpace(in.Name) == "" {
		return fmt.Errorf("%w: an app needs a name", ErrBadRequest)
	}
	if strings.TrimSpace(in.PackageID) == "" {
		return fmt.Errorf("%w: an app needs a winget package id", ErrBadRequest)
	}
	// Machine scope is the only one. The agent runs as the system account, so
	// a per-user install would land in its profile rather than a person's.
	if in.Scope != "" && in.Scope != protocol.ScopeMachine {
		return fmt.Errorf("%w: scope must be %q", ErrBadRequest, protocol.ScopeMachine)
	}
	return nil
}

// Create adds an app and its first version.
func (s *Service) Create(ctx context.Context, in NewApp) (store.App, error) {
	if err := in.validate(); err != nil {
		return store.App{}, err
	}
	scope := in.Scope
	if scope == "" {
		scope = protocol.ScopeMachine
	}
	now := s.now()
	a := store.App{
		ID: uuid.Must(uuid.NewV7()), Name: strings.TrimSpace(in.Name), Description: in.Description,
		CurrentVersion: 1, CreatedAt: now, UpdatedAt: now, CreatedBy: in.Actor,
	}
	err := s.Store.InTx(ctx, func(q *store.Queries) error {
		if _, err := q.GetAppByName(ctx, a.Name); err == nil {
			return ErrNameTaken
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}
		if err := q.CreateApp(ctx, a); err != nil {
			return err
		}
		if err := q.CreateAppVersion(ctx, store.AppVersion{
			AppID: a.ID, Version: 1, PackageID: in.PackageID, PinnedVersion: in.PinnedVersion,
			Scope: scope, InstallArgs: in.InstallArgs,
			Hash: Hash(in.PackageID, in.PinnedVersion, scope, in.InstallArgs), CreatedAt: now, CreatedBy: in.Actor,
		}); err != nil {
			return err
		}
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: in.Actor, Action: "app.created", TargetKind: "app", TargetID: a.ID.String(),
			Details: map[string]any{"name": a.Name},
		})
	})
	if err != nil {
		return store.App{}, err
	}
	return a, nil
}

// Update changes an app. A new version is written only when the winget
// package, pin, scope or arguments actually changed, so renaming does not
// make every device install it again.
func (s *Service) Update(ctx context.Context, id uuid.UUID, in NewApp) (store.App, error) {
	if err := in.validate(); err != nil {
		return store.App{}, err
	}
	scope := in.Scope
	if scope == "" {
		scope = protocol.ScopeMachine
	}
	now := s.now()
	var out store.App
	err := s.Store.InTx(ctx, func(q *store.Queries) error {
		a, err := q.GetApp(ctx, store.DefaultTenantID, id)
		if errors.Is(err, store.ErrNotFound) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		name := strings.TrimSpace(in.Name)
		if other, err := q.GetAppByName(ctx, name); err == nil && other.ID != id {
			return ErrNameTaken
		} else if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}

		current, err := q.GetAppVersion(ctx, id, a.CurrentVersion)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		newHash := Hash(in.PackageID, in.PinnedVersion, scope, in.InstallArgs)
		newVersion := current.Hash != newHash
		if newVersion {
			a.CurrentVersion++
			if err := q.CreateAppVersion(ctx, store.AppVersion{
				AppID: id, Version: a.CurrentVersion, PackageID: in.PackageID, PinnedVersion: in.PinnedVersion,
				Scope: scope, InstallArgs: in.InstallArgs, Hash: newHash, CreatedAt: now, CreatedBy: in.Actor,
			}); err != nil {
				return err
			}
		}
		a.Name, a.Description, a.UpdatedAt = name, in.Description, now
		if err := q.UpdateApp(ctx, store.DefaultTenantID, a); err != nil {
			return err
		}
		out = a
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: in.Actor, Action: "app.updated", TargetKind: "app", TargetID: id.String(),
			Details: map[string]any{"name": a.Name, "new_version": newVersion, "version": a.CurrentVersion},
		})
	})
	if err != nil {
		return store.App{}, err
	}
	return out, nil
}

// Delete removes an app, its versions and its assignments. Installs are kept.
func (s *Service) Delete(ctx context.Context, id uuid.UUID, actor string) error {
	return s.Store.InTx(ctx, func(q *store.Queries) error {
		a, err := q.GetApp(ctx, store.DefaultTenantID, id)
		if errors.Is(err, store.ErrNotFound) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if err := q.DeleteAssignmentsForItem(ctx, protocol.ItemKindApp, id); err != nil {
			return err
		}
		if err := q.DeleteApp(ctx, store.DefaultTenantID, id); err != nil {
			return err
		}
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: actor, Action: "app.deleted", TargetKind: "app", TargetID: id.String(),
			Details: map[string]any{"name": a.Name},
		})
	})
}

func (s *Service) Get(ctx context.Context, id uuid.UUID) (store.App, error) {
	a, err := s.Store.Q().GetApp(ctx, store.DefaultTenantID, id)
	if errors.Is(err, store.ErrNotFound) {
		return store.App{}, ErrNotFound
	}
	return a, err
}

func (s *Service) List(ctx context.Context, page store.Page) ([]store.App, int, error) {
	return s.Store.Q().ListApps(ctx, page)
}

func (s *Service) Version(ctx context.Context, id uuid.UUID, version int) (store.AppVersion, error) {
	v, err := s.Store.Q().GetAppVersion(ctx, id, version)
	if errors.Is(err, store.ErrNotFound) {
		return store.AppVersion{}, ErrNotFound
	}
	return v, err
}

func (s *Service) ListVersions(ctx context.Context, id uuid.UUID) ([]store.AppVersion, error) {
	return s.Store.Q().ListAppVersions(ctx, id)
}

// RecordInstall stores one reported install or uninstall and updates the
// device's status for that app, both in one transaction so the summary can
// never disagree with the history.
func (s *Service) RecordInstall(ctx context.Context, deviceID, appID uuid.UUID, r protocol.AppResult) error {
	switch r.Status {
	case protocol.ResultSucceeded, protocol.ResultFailed:
	default:
		return fmt.Errorf("%w: unsupported install status %q", ErrBadRequest, r.Status)
	}
	switch r.Intent {
	case protocol.IntentInstall, protocol.IntentUninstall:
	default:
		return fmt.Errorf("%w: unsupported intent %q", ErrBadRequest, r.Intent)
	}

	now := s.now()
	stdout, stdoutTruncated := clamp(r.Stdout, r.StdoutTruncated)
	stderr, stderrTruncated := clamp(r.Stderr, r.StderrTruncated)
	errText, _ := clamp(r.Error, false)
	detail, _ := clamp(r.Detail, false)

	status := store.ItemSucceeded
	if r.Status != protocol.ResultSucceeded {
		status = store.ItemFailed
	}
	if detail == "" && r.Status == protocol.ResultSucceeded {
		switch {
		case r.Intent == protocol.IntentUninstall:
			detail = "removed"
		case r.InstalledVersion != "":
			detail = "installed " + r.InstalledVersion
		}
	} else if detail == "" {
		// Naming the package lets an administrator tell two failing apps
		// apart from the rollup alone, without opening the install history
		// first. The version is immutable, so this lookup can never disagree
		// with what actually ran.
		packageID := "?"
		if v, err := s.Store.Q().GetAppVersion(ctx, appID, r.Version); err == nil {
			packageID = v.PackageID
		}
		switch {
		case strings.HasPrefix(errText, "timed out after"):
			detail = fmt.Sprintf("%s: %s, and the install may still be running", packageID, errText)
		case errText != "":
			detail = fmt.Sprintf("%s: %s", packageID, errText)
		default:
			detail = fmt.Sprintf("%s: winget exited %d", packageID, r.ExitCode)
		}
	}

	return s.Store.InTx(ctx, func(q *store.Queries) error {
		if err := q.InsertAppInstall(ctx, store.AppInstall{
			ID: uuid.Must(uuid.NewV7()), AppID: appID, Version: r.Version, DeviceID: deviceID,
			Intent: r.Intent, Status: r.Status, InstalledVersion: r.InstalledVersion,
			ExitCode: r.ExitCode, Stdout: stdout, Stderr: stderr,
			StdoutTruncated: stdoutTruncated, StderrTruncated: stderrTruncated,
			Error: errText, Detail: detail, StartedAt: r.StartedAt, FinishedAt: r.FinishedAt,
		}); err != nil {
			return err
		}
		return q.SetItemStatus(ctx, store.ItemStatus{
			DeviceID: deviceID, ItemKind: protocol.ItemKindApp, ItemID: appID,
			Status: status, Detail: detail, Version: r.Version, UpdatedAt: now,
		})
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
