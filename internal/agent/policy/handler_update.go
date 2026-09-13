package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"retune/internal/protocol"
)

// updatePolicyKey is where Windows reads deferral and restart policy from.
const updatePolicyKey = `SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`

// WindowsUpdateHandler configures Windows Update through its policy registry
// values. Expressing it as a translation to registry settings means the fiddly
// part is implemented once, in the registry handler, and the translation itself
// is a pure function.
type WindowsUpdateHandler struct {
	// Registry applies the values. Tests replace it.
	Registry Handler
}

func (WindowsUpdateHandler) Kind() string { return protocol.KindWindowsUpdate }

func (h WindowsUpdateHandler) registry() Handler {
	if h.Registry != nil {
		return h.Registry
	}
	return RegistryHandler{}
}

// UpdatePolicyValues turns an update setting into the registry values that
// express it. Values the setting does not mention are left out entirely, so a
// profile that only defers quality updates does not silently reset active
// hours.
func UpdatePolicyValues(s protocol.Setting) []protocol.Setting {
	var out []protocol.Setting
	dword := func(name string, value int) {
		out = append(out, protocol.Setting{
			Kind: protocol.KindRegistry, Hive: "HKLM", Key: updatePolicyKey,
			Name: name, Type: protocol.RegDWord, Data: strconv.Itoa(value),
		})
	}

	if s.QualityDeferralDays != nil {
		dword("DeferQualityUpdates", 1)
		dword("DeferQualityUpdatesPeriodInDays", *s.QualityDeferralDays)
	}
	if s.FeatureDeferralDays != nil {
		dword("DeferFeatureUpdates", 1)
		dword("DeferFeatureUpdatesPeriodInDays", *s.FeatureDeferralDays)
	}
	if s.ActiveHoursStart != nil && s.ActiveHoursEnd != nil {
		dword("SetActiveHours", 1)
		dword("ActiveHoursStart", *s.ActiveHoursStart)
		dword("ActiveHoursEnd", *s.ActiveHoursEnd)
	}
	if s.AutoRestart != nil {
		// The policy is phrased the other way round: 1 means do not reboot
		// while someone is signed in.
		value := 1
		if *s.AutoRestart {
			value = 0
		}
		dword("NoAutoRebootWithLoggedOnUsers", value)
	}
	return out
}

// updateState is what the policy looked like before, one entry per value.
type updateState struct {
	Values map[string]State `json:"values"`
}

func (h WindowsUpdateHandler) Get(ctx context.Context, s protocol.Setting) (State, error) {
	was := updateState{Values: map[string]State{}}
	for _, value := range UpdatePolicyValues(s) {
		prior, err := h.registry().Get(ctx, value)
		if err != nil {
			return State{}, err
		}
		was.Values[value.Name] = prior
	}
	raw, err := json.Marshal(was)
	if err != nil {
		return State{}, err
	}
	// Exists reports whether any of the policy was already set, which is what
	// decides whether a revert restores values or removes them.
	exists := false
	for _, v := range was.Values {
		if v.Exists {
			exists = true
		}
	}
	return State{Exists: exists, Data: raw}, nil
}

func (h WindowsUpdateHandler) Test(ctx context.Context, s protocol.Setting) (bool, error) {
	for _, value := range UpdatePolicyValues(s) {
		ok, err := h.registry().Test(ctx, value)
		if err != nil || !ok {
			return false, err
		}
	}
	return true, nil
}

func (h WindowsUpdateHandler) Set(ctx context.Context, s protocol.Setting) error {
	for _, value := range UpdatePolicyValues(s) {
		if err := h.registry().Set(ctx, value); err != nil {
			return fmt.Errorf("%s: %w", value.Name, err)
		}
	}
	return nil
}

// Revert puts each policy value back as it was, which for a machine that had no
// policy means removing them.
func (h WindowsUpdateHandler) Revert(ctx context.Context, s protocol.Setting, prior State) error {
	reverter, ok := h.registry().(Reverter)
	if !ok {
		return fmt.Errorf("the registry handler cannot revert")
	}
	var was updateState
	if len(prior.Data) > 0 {
		if err := json.Unmarshal(prior.Data, &was); err != nil {
			return err
		}
	}
	for _, value := range UpdatePolicyValues(s) {
		if err := reverter.Revert(ctx, value, was.Values[value.Name]); err != nil {
			return fmt.Errorf("%s: %w", value.Name, err)
		}
	}
	return nil
}
