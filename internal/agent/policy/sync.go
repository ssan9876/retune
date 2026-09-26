package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"retune/internal/opsign"
	"retune/internal/protocol"
)

// Fetcher downloads the settings of one profile version.
type Fetcher interface {
	FetchProfile(ctx context.Context, profileID string, version int) (protocol.ProfileVersionResponse, error)
}

// Cache holds profile versions so the settings are fetched once per version
// rather than on every check-in.
type Cache interface {
	CachedProfile(id string, version int) (protocol.ProfileVersionResponse, bool, error)
	CacheProfile(id string, v protocol.ProfileVersionResponse) error
}

// Syncer turns the items from a check-in into a reconcile.
type Syncer struct {
	Reconciler *Reconciler
	Fetcher    Fetcher
	Cache      Cache
	Log        *slog.Logger
	// Operations is what this agent was built to require. Enforced, a
	// profile version not signed by a trusted operations key is held: not
	// applied, not undone, and reported as refused.
	Operations opsign.Policy
}

func (s *Syncer) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.New(slog.DiscardHandler)
}

// Sync reconciles the profiles among a check-in's items. Items of other kinds
// are ignored, which is how an older agent copes with a newer server.
//
// It runs even when no profile is assigned, because that is exactly when a
// profile that has just been unassigned needs to be undone.
func (s *Syncer) Sync(ctx context.Context, items []protocol.Item) error {
	var assigned []Assigned
	for _, item := range items {
		if item.Kind != protocol.ItemKindProfile {
			continue
		}
		version, err := s.settings(ctx, item)
		if err != nil {
			// A profile that cannot be fetched is left out of this cycle; the
			// others still apply.
			s.log().Warn("fetching a profile failed", "profile_id", item.ID, "error", err)
			continue
		}
		var opts protocol.ProfileOptions
		if len(item.Options) > 0 {
			if err := unmarshalOptions(item.Options, &opts); err != nil {
				s.log().Warn("reading a profile's options failed", "profile_id", item.ID, "error", err)
			}
		}
		a := Assigned{
			ProfileID: item.ID, Version: item.Version,
			Settings: version.Settings, Options: opts,
		}
		// Checked on every cycle, cached or not.
		if s.Operations.Enforced {
			if err := opsign.Verify(s.Operations.Keys, protocol.ProfileManifest(version.Settings), version.Signature); err != nil {
				a.Held = "refused: " + err.Error()
				s.log().Warn("not applying a profile", "profile_id", item.ID, "version", item.Version, "error", err)
			}
		}
		assigned = append(assigned, a)
	}
	return s.Reconciler.Reconcile(ctx, assigned)
}

func (s *Syncer) settings(ctx context.Context, item protocol.Item) (protocol.ProfileVersionResponse, error) {
	if s.Cache != nil {
		cached, found, err := s.Cache.CachedProfile(item.ID, item.Version)
		if err == nil && found {
			return cached, nil
		}
	}
	fetched, err := s.Fetcher.FetchProfile(ctx, item.ID, item.Version)
	if err != nil {
		return protocol.ProfileVersionResponse{}, err
	}
	if s.Cache != nil {
		if err := s.Cache.CacheProfile(item.ID, fetched); err != nil {
			return protocol.ProfileVersionResponse{}, fmt.Errorf("cache the profile: %w", err)
		}
	}
	return fetched, nil
}

func unmarshalOptions(raw []byte, out *protocol.ProfileOptions) error {
	return json.Unmarshal(raw, out)
}
