// Package profiles owns the configuration profile library and the per-setting
// results devices report back.
package profiles

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"retune/internal/protocol"
	"retune/internal/server/secrets"
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
	// Key seals the secrets some settings carry, such as Wi-Fi passphrases.
	Key *secrets.Key
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

// prepare checks a profile's settings and returns them as stored: secrets
// sealed, and a secret left blank in an edit carried over from current, the
// settings the profile has now.
func (s *Service) prepare(in NewProfile, profileID uuid.UUID, current []protocol.Setting) ([]byte, error) {
	if strings.TrimSpace(in.Name) == "" {
		return nil, fmt.Errorf("%w: a profile needs a name", ErrBadRequest)
	}
	if len(in.Settings) > MaxSettings {
		return nil, fmt.Errorf("%w: a profile may have at most %d settings", ErrBadRequest, MaxSettings)
	}
	settings := make([]protocol.Setting, len(in.Settings))
	copy(settings, in.Settings)
	kept := map[string]*protocol.SealedSecret{}
	for _, c := range current {
		if c.SealedSecret != nil {
			kept[c.Identity()] = c.SealedSecret
		}
	}
	for i := range settings {
		// Only the server makes sealed secrets; one in a request is ignored.
		settings[i].SealedSecret, settings[i].SecretSet = nil, false
		if settings[i].HasSecret() && settings[i].Passphrase == "" && settings[i].NeedsSecret() {
			settings[i].SealedSecret = kept[settings[i].Identity()]
		}
	}
	if err := protocol.ValidateSettings(settings); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadRequest, err)
	}
	for i := range settings {
		if settings[i].Passphrase == "" {
			continue
		}
		sealed, err := s.seal(profileID, settings[i])
		if err != nil {
			return nil, err
		}
		settings[i].Passphrase, settings[i].SealedSecret = "", sealed
	}
	// Store the canonical form, so an edit that only reorders JSON keys does
	// not look like a change.
	return json.Marshal(settings)
}

// secretContext binds a sealed secret to its profile and setting, so one
// copied elsewhere doesn't open.
func secretContext(profileID uuid.UUID, identity string) []byte {
	return []byte("profile-secret:" + profileID.String() + "/" + identity)
}

func (s *Service) seal(profileID uuid.UUID, setting protocol.Setting) (*protocol.SealedSecret, error) {
	if s.Key == nil {
		return nil, fmt.Errorf("%w: this server has no key to protect passphrases with", ErrBadRequest)
	}
	ctx := secretContext(profileID, setting.Identity())
	ct, nonce, err := s.Key.Seal([]byte(setting.Passphrase), ctx)
	if err != nil {
		return nil, err
	}
	enc := base64.StdEncoding
	return &protocol.SealedSecret{
		Ciphertext: enc.EncodeToString(ct), Nonce: enc.EncodeToString(nonce),
		MAC: enc.EncodeToString(s.Key.MAC([]byte(setting.Passphrase), ctx)),
	}, nil
}

// ResealSettings re-encrypts the secrets in one version's stored settings from
// one server key to another, for key rotation, and returns the settings and
// the version hash to store. A version with no secrets is unchanged.
func ResealSettings(from, to *secrets.Key, profileID uuid.UUID, stored []byte) (settings []byte, hash string, changed bool, err error) {
	var list []protocol.Setting
	if err := json.Unmarshal(stored, &list); err != nil {
		return nil, "", false, fmt.Errorf("decode stored settings: %w", err)
	}
	opener := &Service{Key: from}
	sealer := &Service{Key: to}
	for i, st := range list {
		if st.SealedSecret == nil {
			continue
		}
		opened, err := opener.ForAgent(profileID, []protocol.Setting{st})
		if err != nil {
			return nil, "", false, err
		}
		sealed, err := sealer.seal(profileID, opened[0])
		if err != nil {
			return nil, "", false, err
		}
		list[i].SealedSecret = sealed
		changed = true
	}
	if !changed {
		return stored, "", false, nil
	}
	if settings, err = json.Marshal(list); err != nil {
		return nil, "", false, err
	}
	// The hash counts a secret by its MAC, which the new key changes.
	hash, err = versionHash(settings)
	return settings, hash, true, err
}

// versionHash identifies stored settings for "did anything change": a sealed
// secret counts by its MAC, since its ciphertext differs every time it is
// sealed.
func versionHash(stored []byte) (string, error) {
	var settings []protocol.Setting
	if len(stored) > 0 {
		if err := json.Unmarshal(stored, &settings); err != nil {
			return "", fmt.Errorf("decode stored settings: %w", err)
		}
	}
	for i := range settings {
		if settings[i].SealedSecret != nil {
			settings[i].SealedSecret = &protocol.SealedSecret{MAC: settings[i].SealedSecret.MAC}
		}
	}
	raw, err := json.Marshal(settings)
	if err != nil {
		return "", err
	}
	return Hash(raw), nil
}

// Redact is settings as an admin sees them: a secret is only SecretSet.
func Redact(settings []protocol.Setting) []protocol.Setting {
	out := make([]protocol.Setting, len(settings))
	for i, st := range settings {
		if st.HasSecret() {
			st.SecretSet = st.SealedSecret != nil || st.Passphrase != ""
			st.Passphrase, st.SealedSecret = "", nil
		}
		out[i] = st
	}
	return out
}

// ForAgent is settings as a device receives them: secrets opened.
func (s *Service) ForAgent(profileID uuid.UUID, settings []protocol.Setting) ([]protocol.Setting, error) {
	out := make([]protocol.Setting, len(settings))
	for i, st := range settings {
		if st.SealedSecret != nil {
			if s.Key == nil {
				return nil, errors.New("this server has no key to open passphrases with")
			}
			enc := base64.StdEncoding
			ct, err := enc.DecodeString(st.SealedSecret.Ciphertext)
			if err != nil {
				return nil, err
			}
			nonce, err := enc.DecodeString(st.SealedSecret.Nonce)
			if err != nil {
				return nil, err
			}
			plain, err := s.Key.Open(ct, nonce, secretContext(profileID, st.Identity()))
			if err != nil {
				return nil, fmt.Errorf("open the secret for %s: %w", st.Identity(), err)
			}
			st.Passphrase, st.SealedSecret = string(plain), nil
		}
		out[i] = st
	}
	return out, nil
}

// Create adds a profile and its first version.
func (s *Service) Create(ctx context.Context, in NewProfile) (store.Profile, error) {
	now := s.now()
	p := store.Profile{
		ID: uuid.Must(uuid.NewV7()), Name: strings.TrimSpace(in.Name), Description: in.Description,
		CurrentVersion: 1, CreatedAt: now, UpdatedAt: now, CreatedBy: in.Actor,
	}
	settings, err := s.prepare(in, p.ID, nil)
	if err != nil {
		return store.Profile{}, err
	}
	hash, err := versionHash(settings)
	if err != nil {
		return store.Profile{}, err
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
			ProfileID: p.ID, Version: 1, Settings: settings, Hash: hash,
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
	if strings.TrimSpace(in.Name) == "" {
		return store.Profile{}, fmt.Errorf("%w: a profile needs a name", ErrBadRequest)
	}
	now := s.now()
	var out store.Profile
	err := s.Store.InTx(ctx, func(q *store.Queries) error {
		p, err := q.GetProfile(ctx, store.DefaultTenantID, id)
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

		current, err := q.GetProfileVersion(ctx, store.DefaultTenantID, id, p.CurrentVersion)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		var currentSettings []protocol.Setting
		if len(current.Settings) > 0 {
			if err := json.Unmarshal(current.Settings, &currentSettings); err != nil {
				return fmt.Errorf("decode stored settings: %w", err)
			}
		}
		settings, err := s.prepare(in, id, currentSettings)
		if err != nil {
			return err
		}
		// Compare canonically: the stored copy came back through jsonb, which
		// normalises spacing and key order, so comparing it to freshly
		// marshalled JSON would call every save a change.
		currentHash, err := versionHash(current.Settings)
		if err != nil {
			return err
		}
		hash, err := versionHash(settings)
		if err != nil {
			return err
		}
		newVersion := currentHash != hash
		if newVersion {
			p.CurrentVersion++
			if err := q.CreateProfileVersion(ctx, store.ProfileVersion{
				ProfileID: id, Version: p.CurrentVersion, Settings: settings, Hash: hash,
				CreatedAt: now, CreatedBy: in.Actor,
			}); err != nil {
				return err
			}
		}
		p.Name, p.Description, p.UpdatedAt = name, in.Description, now
		if err := q.UpdateProfile(ctx, store.DefaultTenantID, p); err != nil {
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
		p, err := q.GetProfile(ctx, store.DefaultTenantID, id)
		if errors.Is(err, store.ErrNotFound) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if err := q.DeleteAssignmentsForItem(ctx, protocol.ItemKindProfile, id); err != nil {
			return err
		}
		if err := q.DeleteProfile(ctx, store.DefaultTenantID, id); err != nil {
			return err
		}
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: actor, Action: "profile.deleted", TargetKind: "profile", TargetID: id.String(),
			Details: map[string]any{"name": p.Name},
		})
	})
}

func (s *Service) Get(ctx context.Context, id uuid.UUID) (store.Profile, error) {
	p, err := s.Store.Q().GetProfile(ctx, store.DefaultTenantID, id)
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
	v, err := s.Store.Q().GetProfileVersion(ctx, store.DefaultTenantID, id, version)
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
			protocol.SettingError, protocol.SettingConflict, protocol.SettingNotApplicable:
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
			// The agent knows profiles only by id. An administrator reading a
			// conflict needs names.
			detail := s.nameProfiles(ctx, q, r.Detail)
			if err := q.SetSettingStatus(ctx, store.SettingStatus{
				DeviceID: deviceID, ProfileID: profileID, Identity: r.Identity,
				Version: report.Version, Status: r.Status, Detail: detail, UpdatedAt: now,
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

// uuidPattern matches the profile ids an agent puts in a conflict detail.
var uuidPattern = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)

// nameProfiles replaces profile ids in a detail with their names, because the
// agent knows only ids and a person reading a conflict needs names.
func (s *Service) nameProfiles(ctx context.Context, q *store.Queries, detail string) string {
	if detail == "" {
		return detail
	}
	return uuidPattern.ReplaceAllStringFunc(detail, func(raw string) string {
		id, err := uuid.Parse(raw)
		if err != nil {
			return raw
		}
		p, err := q.GetProfile(ctx, store.DefaultTenantID, id)
		if err != nil {
			// The profile has gone; the id is still better than nothing.
			return raw
		}
		return p.Name
	})
}
