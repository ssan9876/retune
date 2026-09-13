// Package profiles owns the configuration profile library and the per-setting
// results devices report back.
package profiles

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	// ErrNotFound is returned when a profile or version does not exist.
	ErrNotFound = errors.New("profile not found")
	// ErrNameTaken is returned when a profile name is already in use.
	ErrNameTaken = errors.New("a profile with that name already exists")
	// ErrBadRequest is returned for input the caller can fix.
	ErrBadRequest = errors.New("bad request")
)

// MaxSettings caps one profile. A profile longer than this is really several.
const MaxSettings = 200

// Service owns the profile library.
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

// NewProfile describes a profile to create or update.
type NewProfile struct {
	Name        string
	Description string
	Settings    []protocol.Setting
	Actor       string
}

// Hash identifies a version's settings.
func Hash(settings []byte) string {
	sum := sha256.Sum256(settings)
	return hex.EncodeToString(sum[:])
}

func (in NewProfile) validate() ([]byte, error) {
	if strings.TrimSpace(in.Name) == "" {
		return nil, fmt.Errorf("%w: a profile needs a name", ErrBadRequest)
	}
	if len(in.Settings) > MaxSettings {
		return nil, fmt.Errorf("%w: a profile may have at most %d settings", ErrBadRequest, MaxSettings)
	}
	if err := protocol.ValidateSettings(in.Settings); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadRequest, err)
	}
	// Store the canonical form, so an edit that only reorders JSON keys does
	// not look like a change.
	raw, err := json.Marshal(in.Settings)
	if err != nil {
		return nil, err
	}
	return raw, nil
}

// Create adds a profile and its first version.
func (s *Service) Create(ctx context.Context, in NewProfile) (store.Profile, error) {
	settings, err := in.validate()
	if err != nil {
		return store.Profile{}, err
	}
	now := s.now()
	p := store.Profile{
		ID: uuid.Must(uuid.NewV7()), Name: strings.TrimSpace(in.Name), Description: in.Description,
		CurrentVersion: 1, CreatedAt: now, UpdatedAt: now, CreatedBy: in.Actor,
	}
	err = s.Store.InTx(ctx, func(q *store.Queries) error {
		if _, err := q.GetProfileByName(ctx, p.Name); err == nil {
			return ErrNameTaken
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}
		if err := q.CreateProfile(ctx, p); err != nil {
			return err
		}
		if err := q.CreateProfileVersion(ctx, store.ProfileVersion{
			ProfileID: p.ID, Version: 1, Settings: settings, Hash: Hash(settings),
			CreatedAt: now, CreatedBy: in.Actor,
		}); err != nil {
			return err
		}
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: in.Actor, Action: "profile.created", TargetKind: "profile", TargetID: p.ID.String(),
			Details: map[string]any{"name": p.Name, "settings": len(in.Settings)},
		})
	})
	if err != nil {
		return store.Profile{}, err
	}
	return p, nil
}

// Update changes a profile. A new version is written only when the settings
// actually changed, so renaming does not make every device reconcile again.
func (s *Service) Update(ctx context.Context, id uuid.UUID, in NewProfile) (store.Profile, error) {
	settings, err := in.validate()
	if err != nil {
		return store.Profile{}, err
	}
	now := s.now()
	var out store.Profile
	err = s.Store.InTx(ctx, func(q *store.Queries) error {
		p, err := q.GetProfile(ctx, id)
		if errors.Is(err, store.ErrNotFound) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		name := strings.TrimSpace(in.Name)
		if other, err := q.GetProfileByName(ctx, name); err == nil && other.ID != id {
			return ErrNameTaken
		} else if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}

		current, err := q.GetProfileVersion(ctx, id, p.CurrentVersion)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		// Compare canonically: the stored copy came back through jsonb, which
		// normalises spacing and key order, so comparing it to freshly
		// marshalled JSON would call every save a change.
		currentCanonical, err := canonical(current.Settings)
		if err != nil {
			return err
		}
		newVersion := Hash(currentCanonical) != Hash(settings)
		if newVersion {
			p.CurrentVersion++
			if err := q.CreateProfileVersion(ctx, store.ProfileVersion{
				ProfileID: id, Version: p.CurrentVersion, Settings: settings, Hash: Hash(settings),
				CreatedAt: now, CreatedBy: in.Actor,
			}); err != nil {
				return err
			}
		}
		p.Name, p.Description, p.UpdatedAt = name, in.Description, now
		if err := q.UpdateProfile(ctx, p); err != nil {
			return err
		}
		out = p
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: in.Actor, Action: "profile.updated", TargetKind: "profile", TargetID: id.String(),
			Details: map[string]any{"name": p.Name, "new_version": newVersion, "version": p.CurrentVersion},
		})
	})
	if err != nil {
		return store.Profile{}, err
	}
	return out, nil
}

// Delete removes a profile, its versions and its assignments.
func (s *Service) Delete(ctx context.Context, id uuid.UUID, actor string) error {
	return s.Store.InTx(ctx, func(q *store.Queries) error {
		p, err := q.GetProfile(ctx, id)
		if errors.Is(err, store.ErrNotFound) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if err := q.DeleteAssignmentsForItem(ctx, protocol.ItemKindProfile, id); err != nil {
			return err
		}
		if err := q.DeleteProfile(ctx, id); err != nil {
			return err
		}
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: actor, Action: "profile.deleted", TargetKind: "profile", TargetID: id.String(),
			Details: map[string]any{"name": p.Name},
		})
	})
}

func (s *Service) Get(ctx context.Context, id uuid.UUID) (store.Profile, error) {
	p, err := s.Store.Q().GetProfile(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return store.Profile{}, ErrNotFound
	}
	return p, err
}

func (s *Service) List(ctx context.Context, page store.Page) ([]store.Profile, int, error) {
	return s.Store.Q().ListProfiles(ctx, page)
}

// Version returns one version's settings, decoded.
func (s *Service) Version(ctx context.Context, id uuid.UUID, version int) (store.ProfileVersion, []protocol.Setting, error) {
	v, err := s.Store.Q().GetProfileVersion(ctx, id, version)
	if errors.Is(err, store.ErrNotFound) {
		return store.ProfileVersion{}, nil, ErrNotFound
	}
	if err != nil {
		return store.ProfileVersion{}, nil, err
	}
	var settings []protocol.Setting
	if err := json.Unmarshal(v.Settings, &settings); err != nil {
		return store.ProfileVersion{}, nil, fmt.Errorf("decode settings: %w", err)
	}
	return v, settings, nil
}

func (s *Service) ListVersions(ctx context.Context, id uuid.UUID) ([]store.ProfileVersion, error) {
	return s.Store.Q().ListProfileVersions(ctx, id)
}

// RecordStatus stores what a device reported for every setting of a profile and
// rolls it up into the profile's own status for that device.
func (s *Service) RecordStatus(ctx context.Context, deviceID, profileID uuid.UUID, report protocol.ProfileStatus) error {
	if len(report.Settings) == 0 {
		return fmt.Errorf("%w: a report needs at least one setting result", ErrBadRequest)
	}
	for _, r := range report.Settings {
		switch r.Status {
		case protocol.SettingCompliant, protocol.SettingRemediated,
			protocol.SettingError, protocol.SettingConflict:
		default:
			return fmt.Errorf("%w: unsupported setting status %q", ErrBadRequest, r.Status)
		}
		if strings.TrimSpace(r.Identity) == "" {
			return fmt.Errorf("%w: every setting result needs an identity", ErrBadRequest)
		}
	}

	now := s.now()
	keep := make([]string, 0, len(report.Settings))
	for _, r := range report.Settings {
		keep = append(keep, r.Identity)
	}
	rollup, detail := rollUp(report.Settings)

	return s.Store.InTx(ctx, func(q *store.Queries) error {
		for _, r := range report.Settings {
			if err := q.SetSettingStatus(ctx, store.SettingStatus{
				DeviceID: deviceID, ProfileID: profileID, Identity: r.Identity,
				Version: report.Version, Status: r.Status, Detail: r.Detail, UpdatedAt: now,
			}); err != nil {
				return err
			}
		}
		// A setting removed from the profile should stop showing its old
		// result.
		if err := q.ClearSettingStatus(ctx, deviceID, profileID, keep); err != nil {
			return err
		}
		return q.SetItemStatus(ctx, store.ItemStatus{
			DeviceID: deviceID, ItemKind: protocol.ItemKindProfile, ItemID: profileID,
			Status: rollup, Detail: detail, Version: report.Version, UpdatedAt: now,
		})
	})
}

// rollUp turns per-setting results into the profile's own status. A conflict
// outranks a failure, because it names something an administrator has to
// decide rather than something that merely went wrong.
func rollUp(results []protocol.SettingResult) (string, string) {
	var conflicts, errored []string
	for _, r := range results {
		switch r.Status {
		case protocol.SettingConflict:
			conflicts = append(conflicts, r.Identity)
		case protocol.SettingError:
			errored = append(errored, r.Identity)
		}
	}
	switch {
	case len(conflicts) > 0:
		return store.ItemConflict, summarize("conflicting", conflicts)
	case len(errored) > 0:
		return store.ItemFailed, summarize("failed", errored)
	}
	return store.ItemSucceeded, ""
}

func summarize(what string, ids []string) string {
	if len(ids) == 1 {
		return ids[0] + " is " + what
	}
	return fmt.Sprintf("%d settings are %s, including %s", len(ids), what, ids[0])
}

// ClearForDevice forgets a profile's results on one device, used when the
// profile stops applying to it.
func (s *Service) ClearForDevice(ctx context.Context, deviceID, profileID uuid.UUID) error {
	return s.Store.Q().ClearDeviceProfileStatus(ctx, deviceID, profileID)
}

// canonical re-encodes stored settings the same way they are written, so a
// round trip through Postgres does not look like an edit.
func canonical(raw []byte) ([]byte, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var settings []protocol.Setting
	if err := json.Unmarshal(raw, &settings); err != nil {
		return nil, fmt.Errorf("decode stored settings: %w", err)
	}
	return json.Marshal(settings)
}
