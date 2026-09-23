package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"retune/internal/protocol"
)

// Record is what the agent remembers about a profile it has applied. It
// outlives the assignment, because once a profile stops applying the server no
// longer tells the agent anything about it — including whether it asked to be
// reverted.
type Record struct {
	// Identities are the settings this profile was responsible for.
	Identities []string `json:"identities"`
	// RevertOnRemoval is the assignment option, kept because it is needed
	// precisely when the assignment is gone.
	RevertOnRemoval bool `json:"revert_on_removal"`
	Version         int  `json:"version"`
}

// Store is the local state the reconciler needs: what was there before Retune
// first changed a setting, and what each applied profile was responsible for.
type Store interface {
	PriorState(identity string) ([]byte, bool, error)
	SetPriorState(identity string, raw []byte) error
	DeletePriorState(identity string) error
	ProfileRecords() (map[string]Record, error)
	SetProfileRecord(profileID string, rec Record) error
	DeleteProfileRecord(profileID string) error
}

// Reporter sends one profile's results to the server.
type Reporter interface {
	ReportProfileStatus(ctx context.Context, profileID string, status protocol.ProfileStatus) error
}

// Reconciler applies assigned profiles and reports what it found.
type Reconciler struct {
	Handlers []Handler
	State    Store
	Client   Reporter
	Log      *slog.Logger

	// mu keeps one reconcile at a time: two of them fighting over the same
	// machine would report nonsense.
	mu sync.Mutex
}

func (r *Reconciler) log() *slog.Logger {
	if r.Log != nil {
		return r.Log
	}
	return slog.New(slog.DiscardHandler)
}

func (r *Reconciler) handlerFor(kind string) Handler {
	for _, h := range r.Handlers {
		if h.Kind() == kind {
			return h
		}
	}
	return nil
}

// Reconcile applies every assigned profile once, undoes any that have gone,
// and reports the outcome.
func (r *Reconciler) Reconcile(ctx context.Context, assigned []Assigned) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	actions, err := Plan(assigned)
	if err != nil {
		return fmt.Errorf("plan: %w", err)
	}

	// Results are collected per profile, because a setting claimed by two
	// profiles is reported to both.
	results := map[string][]protocol.SettingResult{}
	for _, a := range assigned {
		results[a.ProfileID] = nil
	}
	for _, action := range actions {
		status, detail := r.apply(ctx, action)
		for _, profileID := range action.Profiles {
			results[profileID] = append(results[profileID], protocol.SettingResult{
				Identity: action.Identity, Status: status, Detail: detail,
			})
		}
	}

	if err := r.forgetRemoved(ctx, assigned); err != nil {
		r.log().Warn("undoing removed profiles failed", "error", err)
	}

	// Remember what each profile is responsible for, and whether it asked to
	// be undone, so both are still known once it stops applying.
	for _, a := range assigned {
		identities := make([]string, 0, len(a.Settings))
		for _, s := range a.Settings {
			identities = append(identities, s.Identity())
		}
		if err := r.State.SetProfileRecord(a.ProfileID, Record{
			Identities: identities, RevertOnRemoval: a.Options.RevertOnRemoval, Version: a.Version,
		}); err != nil {
			r.log().Warn("recording a profile failed", "profile_id", a.ProfileID, "error", err)
		}
	}

	var reportErr error
	for _, a := range assigned {
		if err := r.Client.ReportProfileStatus(ctx, a.ProfileID, protocol.ProfileStatus{
			Version: a.Version, Settings: results[a.ProfileID],
		}); err != nil && reportErr == nil {
			reportErr = err
		}
	}
	return reportErr
}

// apply reconciles one setting: test, then set only if needed, then test again.
// The second test is what separates "I fixed it" from "I ran something".
func (r *Reconciler) apply(ctx context.Context, action Action) (status, detail string) {
	defer func() {
		if p := recover(); p != nil {
			// One bad setting must not stop the profile.
			status, detail = protocol.SettingError, fmt.Sprintf("the handler panicked: %v", p)
			r.log().Error("setting handler panicked", "identity", action.Identity, "panic", p)
		}
	}()

	if action.Conflict {
		return protocol.SettingConflict, action.Detail
	}
	h := r.handlerFor(action.Setting.Kind)
	if h == nil {
		return protocol.SettingError, fmt.Sprintf("this agent cannot apply %q settings", action.Setting.Kind)
	}

	ok, err := h.Test(ctx, action.Setting)
	if errors.Is(err, ErrNotApplicable) {
		return protocol.SettingNotApplicable, err.Error()
	}
	if err != nil {
		return protocol.SettingError, err.Error()
	}
	if ok {
		return protocol.SettingCompliant, ""
	}

	// Record what was there before the first change, so a revert restores the
	// original rather than whatever Retune last wrote.
	if err := r.rememberPrior(ctx, h, action); err != nil {
		r.log().Warn("recording the previous state failed", "identity", action.Identity, "error", err)
	}

	if err := h.Set(ctx, action.Setting); err != nil {
		return protocol.SettingError, err.Error()
	}

	ok, err = h.Test(ctx, action.Setting)
	switch {
	case err != nil:
		return protocol.SettingError, err.Error()
	case !ok:
		return protocol.SettingError, "the setting was applied but the machine still does not match it"
	}
	return protocol.SettingRemediated, ""
}

func (r *Reconciler) rememberPrior(ctx context.Context, h Handler, action Action) error {
	if _, found, err := r.State.PriorState(action.Identity); err != nil || found {
		return err
	}
	prior, err := h.Get(ctx, action.Setting)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(priorRecord{Kind: action.Setting.Kind, Setting: action.Setting, State: prior})
	if err != nil {
		return err
	}
	return r.State.SetPriorState(action.Identity, raw)
}

// priorRecord is what was there before, kept with the setting that changed it
// so a revert can be carried out even after the profile is gone.
type priorRecord struct {
	Kind    string           `json:"kind"`
	Setting protocol.Setting `json:"setting"`
	State   State            `json:"state"`
}

// forgetRemoved stops enforcing profiles that no longer apply, undoing their
// settings where the assignment asked for it.
func (r *Reconciler) forgetRemoved(ctx context.Context, assigned []Assigned) error {
	records, err := r.State.ProfileRecords()
	if err != nil {
		return err
	}
	current := map[string]bool{}
	stillClaimed := map[string]bool{}
	for _, a := range assigned {
		current[a.ProfileID] = true
		for _, s := range a.Settings {
			stillClaimed[s.Identity()] = true
		}
	}

	for id, rec := range records {
		if current[id] {
			continue
		}
		r.log().Info("a profile no longer applies to this device",
			"profile_id", id, "revert", rec.RevertOnRemoval)
		if rec.RevertOnRemoval {
			r.revert(ctx, rec, stillClaimed)
		}
		if err := r.State.DeleteProfileRecord(id); err != nil {
			return err
		}
	}
	return nil
}

// revert restores what a removed profile changed, leaving alone any setting
// another profile still claims.
func (r *Reconciler) revert(ctx context.Context, rec Record, stillClaimed map[string]bool) {
	for _, id := range rec.Identities {
		if stillClaimed[id] {
			continue
		}
		raw, found, err := r.State.PriorState(id)
		if err != nil || !found {
			continue
		}
		var prior priorRecord
		if err := json.Unmarshal(raw, &prior); err != nil {
			r.log().Warn("the recorded previous state could not be read", "identity", id, "error", err)
			continue
		}
		reverter, ok := r.handlerFor(prior.Kind).(Reverter)
		if !ok {
			continue
		}
		if err := reverter.Revert(ctx, prior.Setting, prior.State); err != nil {
			r.log().Warn("reverting a setting failed", "identity", id, "error", err)
			continue
		}
		if err := r.State.DeletePriorState(id); err != nil {
			r.log().Warn("forgetting a previous state failed", "identity", id, "error", err)
		}
	}
}
