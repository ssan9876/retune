// Package policy keeps a machine matching the configuration profiles assigned
// to it: test each setting, fix what has drifted, and report what it found.
package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"retune/internal/protocol"
)

// State is what a handler found, kept so a setting can be put back.
type State struct {
	Exists bool            `json:"exists"`
	Data   json.RawMessage `json:"data,omitempty"`
}

// Handler applies one kind of setting.
type Handler interface {
	Kind() string
	// Get reports the current state, recorded before the first change so the
	// setting can be reverted to what was there before Retune touched it.
	Get(ctx context.Context, s protocol.Setting) (State, error)
	// Test reports whether the machine already matches the setting.
	Test(ctx context.Context, s protocol.Setting) (bool, error)
	// Set makes it match.
	Set(ctx context.Context, s protocol.Setting) error
}

// Reverter is implemented by handlers that can undo a setting.
type Reverter interface {
	Revert(ctx context.Context, s protocol.Setting, prior State) error
}

// Assigned is one profile a device should be following.
type Assigned struct {
	ProfileID string
	Version   int
	Settings  []protocol.Setting
	Options   protocol.ProfileOptions
	// Held, when set, is why this agent won't apply this version, such as a
	// missing operations signature. A held profile is still assigned: it is
	// neither applied nor undone, and each of its settings is reported as an
	// error saying why.
	Held string
}

// claim is one profile's wish for one setting identity.
type claim struct {
	profileID string
	setting   protocol.Setting
}

// Action is what to do about one setting identity this cycle.
type Action struct {
	Identity string
	Setting  protocol.Setting
	// Profiles are every profile claiming this identity, in assignment order.
	Profiles []string
	// Conflict says the claims disagree, so nothing is applied.
	Conflict bool
	// Detail explains a conflict, naming the profiles involved.
	Detail string
}

// Plan groups the settings of every assigned profile by identity and decides
// which of them can be applied.
//
// Two profiles setting the same identity to different values apply neither:
// picking a winner silently would make a machine's state depend on assignment
// order, which nobody can reason about. Identical values are not a conflict.
func Plan(assigned []Assigned) ([]Action, error) {
	order := []string{}
	claims := map[string][]claim{}
	for _, a := range assigned {
		for _, s := range a.Settings {
			id := s.Identity()
			if _, seen := claims[id]; !seen {
				order = append(order, id)
			}
			claims[id] = append(claims[id], claim{profileID: a.ProfileID, setting: s})
		}
	}

	out := make([]Action, 0, len(order))
	for _, id := range order {
		cs := claims[id]
		a := Action{Identity: id, Setting: cs[0].setting}
		for _, c := range cs {
			a.Profiles = append(a.Profiles, c.profileID)
		}
		same, err := allSame(cs)
		if err != nil {
			return nil, err
		}
		if !same {
			a.Conflict = true
			a.Detail = conflictDetail(a.Profiles)
		}
		out = append(out, a)
	}
	return out, nil
}

// allSame reports whether every claim on an identity asks for the same thing.
func allSame(cs []claim) (bool, error) {
	first, err := json.Marshal(cs[0].setting)
	if err != nil {
		return false, err
	}
	for _, c := range cs[1:] {
		raw, err := json.Marshal(c.setting)
		if err != nil {
			return false, err
		}
		if string(raw) != string(first) {
			return false, nil
		}
	}
	return true, nil
}

func conflictDetail(profileIDs []string) string {
	unique := map[string]bool{}
	var names []string
	for _, id := range profileIDs {
		if !unique[id] {
			unique[id] = true
			names = append(names, id)
		}
	}
	sort.Strings(names)
	return fmt.Sprintf("profiles disagree about this setting: %v", names)
}
