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
	seen := map[string]bool{}
	value := func(name, typ, data string) {
		if seen[name] {
			return
		}
		seen[name] = true
		out = append(out, protocol.Setting{
			Kind: protocol.KindRegistry, Hive: "HKLM", Key: updatePolicyKey,
			Name: name, Type: typ, Data: data,
		})
	}
	dword := func(name string, v int) { value(name, protocol.RegDWord, strconv.Itoa(v)) }
	text := func(name, v string) { value(name, protocol.RegSZ, v) }

	// Pausing is part of the same policy as deferring: the pause date only
	// counts while the deferral policy is on, so a pause with no deferral
	// of its own turns deferral on at zero days, which is the default.
	if s.QualityDeferralDays != nil || s.PauseQualityFrom != "" {
		dword("DeferQualityUpdates", 1)
		dword("DeferQualityUpdatesPeriodInDays", valueOr(s.QualityDeferralDays, 0))
	}
	if s.PauseQualityFrom != "" {
		text("PauseQualityUpdatesStartTime", s.PauseQualityFrom)
	}
	if s.FeatureDeferralDays != nil || s.PauseFeatureFrom != "" {
		dword("DeferFeatureUpdates", 1)
		dword("DeferFeatureUpdatesPeriodInDays", valueOr(s.FeatureDeferralDays, 0))
	}
	if s.PauseFeatureFrom != "" {
		text("PauseFeatureUpdatesStartTime", s.PauseFeatureFrom)
	}
	if s.ActiveHoursStart != nil && s.ActiveHoursEnd != nil {
		dword("SetActiveHours", 1)
		dword("ActiveHoursStart", *s.ActiveHoursStart)
		dword("ActiveHoursEnd", *s.ActiveHoursEnd)
	}
	if s.AutoRestart != nil {
		// The policy is phrased the other way round: 1 means do not reboot
		// while someone is signed in.
		v := 1
		if *s.AutoRestart {
			v = 0
		}
		dword("NoAutoRebootWithLoggedOnUsers", v)
	}
	if s.QualityDeadlineDays != nil || s.FeatureDeadlineDays != nil {
		dword("SetComplianceDeadline", 1)
		if s.QualityDeadlineDays != nil {
			dword("ConfigureDeadlineForQualityUpdates", *s.QualityDeadlineDays)
		}
		if s.FeatureDeadlineDays != nil {
			dword("ConfigureDeadlineForFeatureUpdates", *s.FeatureDeadlineDays)
		}
		if s.DeadlineGraceDays != nil {
			dword("ConfigureDeadlineGracePeriod", *s.DeadlineGraceDays)
			dword("ConfigureDeadlineGracePeriodForFeatureUpdates", *s.DeadlineGraceDays)
		}
	}
	if s.TargetProduct != "" && s.TargetVersion != "" {
		dword("TargetReleaseVersion", 1)
		text("ProductVersion", s.TargetProduct)
		text("TargetReleaseVersionInfo", s.TargetVersion)
	}
	return out
}

func valueOr(p *int, fallback int) int {
	if p == nil {
		return fallback
	}
	return *p
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
