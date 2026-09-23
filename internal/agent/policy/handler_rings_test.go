package policy_test

import (
	"testing"

	"retune/internal/agent/policy"
	"retune/internal/protocol"
)

// values flattens a translation to name -> type:data, failing on a value
// written twice.
func values(t *testing.T, s protocol.Setting) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, v := range policy.UpdatePolicyValues(s) {
		if _, dup := out[v.Name]; dup {
			t.Fatalf("%s is written twice", v.Name)
		}
		if err := v.Validate(); err != nil {
			t.Fatalf("%s is not a valid registry setting: %v", v.Name, err)
		}
		out[v.Name] = v.Type + ":" + v.Data
	}
	return out
}

func check(t *testing.T, got, want map[string]string) {
	t.Helper()
	for name, value := range want {
		if got[name] != value {
			t.Errorf("%s = %q, want %q", name, got[name], value)
		}
	}
	if len(got) != len(want) {
		t.Errorf("wrote %d values, want %d: %v", len(got), len(want), got)
	}
}

func TestUpdateDeadlines(t *testing.T) {
	check(t, values(t, protocol.Setting{
		Kind: protocol.KindWindowsUpdate, QualityDeadlineDays: intp(3), FeatureDeadlineDays: intp(7),
		DeadlineGraceDays: intp(2),
	}), map[string]string{
		"SetComplianceDeadline":                         "REG_DWORD:1",
		"ConfigureDeadlineForQualityUpdates":            "REG_DWORD:3",
		"ConfigureDeadlineForFeatureUpdates":            "REG_DWORD:7",
		"ConfigureDeadlineGracePeriod":                  "REG_DWORD:2",
		"ConfigureDeadlineGracePeriodForFeatureUpdates": "REG_DWORD:2",
	})

	// Only the deadline asked for; a quality deadline doesn't touch feature
	// updates.
	check(t, values(t, protocol.Setting{Kind: protocol.KindWindowsUpdate, QualityDeadlineDays: intp(0)}),
		map[string]string{
			"SetComplianceDeadline":              "REG_DWORD:1",
			"ConfigureDeadlineForQualityUpdates": "REG_DWORD:0",
		})
}

func TestUpdatePause(t *testing.T) {
	// A pause alone turns the deferral policy on at zero days, since the
	// pause date is part of that policy.
	check(t, values(t, protocol.Setting{Kind: protocol.KindWindowsUpdate, PauseQualityFrom: "2026-09-22"}),
		map[string]string{
			"DeferQualityUpdates":             "REG_DWORD:1",
			"DeferQualityUpdatesPeriodInDays": "REG_DWORD:0",
			"PauseQualityUpdatesStartTime":    "REG_SZ:2026-09-22",
		})

	// With a deferral of its own, the deferral is kept and not written twice.
	check(t, values(t, protocol.Setting{
		Kind: protocol.KindWindowsUpdate, FeatureDeferralDays: intp(30), PauseFeatureFrom: "2026-09-22",
	}), map[string]string{
		"DeferFeatureUpdates":             "REG_DWORD:1",
		"DeferFeatureUpdatesPeriodInDays": "REG_DWORD:30",
		"PauseFeatureUpdatesStartTime":    "REG_SZ:2026-09-22",
	})
}

func TestUpdateTargetRelease(t *testing.T) {
	check(t, values(t, protocol.Setting{
		Kind: protocol.KindWindowsUpdate, TargetProduct: "Windows 11", TargetVersion: "24H2",
	}), map[string]string{
		"TargetReleaseVersion":     "REG_DWORD:1",
		"ProductVersion":           "REG_SZ:Windows 11",
		"TargetReleaseVersionInfo": "REG_SZ:24H2",
	})
}

func TestUpdateRingValidation(t *testing.T) {
	good := []protocol.Setting{
		{Kind: protocol.KindWindowsUpdate, QualityDeadlineDays: intp(0)},
		{Kind: protocol.KindWindowsUpdate, FeatureDeadlineDays: intp(30), DeadlineGraceDays: intp(7)},
		{Kind: protocol.KindWindowsUpdate, PauseQualityFrom: "2026-09-22"},
		{Kind: protocol.KindWindowsUpdate, TargetProduct: "Windows 10", TargetVersion: "22H2"},
	}
	for _, s := range good {
		if err := s.Validate(); err != nil {
			t.Errorf("%+v: %v", s, err)
		}
	}
	bad := map[string]protocol.Setting{
		"deadline too long":  {Kind: protocol.KindWindowsUpdate, QualityDeadlineDays: intp(31)},
		"negative deadline":  {Kind: protocol.KindWindowsUpdate, FeatureDeadlineDays: intp(-1)},
		"grace too long":     {Kind: protocol.KindWindowsUpdate, QualityDeadlineDays: intp(1), DeadlineGraceDays: intp(8)},
		"grace alone":        {Kind: protocol.KindWindowsUpdate, DeadlineGraceDays: intp(2)},
		"not a date":         {Kind: protocol.KindWindowsUpdate, PauseQualityFrom: "22/09/2026"},
		"product alone":      {Kind: protocol.KindWindowsUpdate, TargetProduct: "Windows 11"},
		"version alone":      {Kind: protocol.KindWindowsUpdate, TargetVersion: "24H2"},
		"unknown product":    {Kind: protocol.KindWindowsUpdate, TargetProduct: "Windows 12", TargetVersion: "24H2"},
		"not a release":      {Kind: protocol.KindWindowsUpdate, TargetProduct: "Windows 11", TargetVersion: "2024"},
		"nothing set at all": {Kind: protocol.KindWindowsUpdate},
	}
	for name, s := range bad {
		if err := s.Validate(); err == nil {
			t.Errorf("%s: should be refused", name)
		}
	}
}
