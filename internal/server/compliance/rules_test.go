package compliance_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"retune/internal/protocol"
	"retune/internal/server/compliance"
	"retune/internal/server/store"
)

func mustParse(t *testing.T, raw string) []compliance.Rule {
	t.Helper()
	rules, err := compliance.ParseRules([]byte(raw))
	if err != nil {
		t.Fatalf("ParseRules(%s): unexpected error: %v", raw, err)
	}
	return rules
}

func ts(hoursAgo float64, now time.Time) *time.Time {
	t := now.Add(-time.Duration(hoursAgo * float64(time.Hour)))
	return &t
}

func TestParseRulesRejections(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"empty array", `[]`},
		{"not an array", `{"type":"tpm"}`},
		{"unknown type", `[{"type":"nonsense"}]`},
		{"unknown field", `[{"type":"tpm","frobnicate":true}]`},
		{"os build empty", `[{"type":"os_build_min","build":""}]`},
		{"os build non numeric", `[{"type":"os_build_min","build":"abc"}]`},
		{"agent version not dotted", `[{"type":"agent_version_min","version":"latest"}]`},
		{"bitlocker bad volumes", `[{"type":"bitlocker","volumes":"partial"}]`},
		{"tpm bad min_version", `[{"type":"tpm","min_version":"vNext"}]`},
		{"checked_in_within hours zero", `[{"type":"checked_in_within","hours":0}]`},
		{"checked_in_within hours too high", `[{"type":"checked_in_within","hours":8761}]`},
		{"inventory_within hours zero", `[{"type":"inventory_within","hours":0}]`},
		{"inventory_within hours too high", `[{"type":"inventory_within","hours":8761}]`},
		{"updates_within days zero", `[{"type":"updates_within","days":0}]`},
		{"updates_within days too high", `[{"type":"updates_within","days":366}]`},
		{"max_local_admins count negative", `[{"type":"max_local_admins","count":-1}]`},
		{"max_local_admins count too high", `[{"type":"max_local_admins","count":101}]`},
		{"forbidden_software empty name", `[{"type":"forbidden_software","name":""}]`},
		{"forbidden_software name too long", `[{"type":"forbidden_software","name":"` + strings.Repeat("a", 201) + `"}]`},
		{"required_software empty name", `[{"type":"required_software","name":""}]`},
		{"profile_applied bad uuid", `[{"type":"profile_applied","profile_id":"not-a-uuid"}]`},
		{"51 rules", "[" + strings.TrimSuffix(strings.Repeat(`{"type":"no_pending_reboot"},`, 51), ",") + "]"},

		// Cross-type field leakage: a field that is a legitimate parameter
		// of some other rule type must still be rejected for this one -
		// DisallowUnknownFields on a single flat struct would silently drop
		// these rather than reject them.
		{"os_build_min leaks version", `[{"type":"os_build_min","build":"26100","version":"1.0"}]`},
		{"agent_version_min leaks build", `[{"type":"agent_version_min","version":"1.0","build":"26100"}]`},
		{"bitlocker leaks hours", `[{"type":"bitlocker","volumes":"system","hours":24}]`},
		{"tpm leaks count", `[{"type":"tpm","min_version":"2.0","count":1}]`},
		{"checked_in_within leaks days", `[{"type":"checked_in_within","hours":24,"days":1}]`},
		{"inventory_within leaks name", `[{"type":"inventory_within","hours":24,"name":"x"}]`},
		{"updates_within leaks build", `[{"type":"updates_within","days":30,"build":"26100"}]`},
		{"no_pending_reboot leaks hours", `[{"type":"no_pending_reboot","hours":999}]`},
		{"max_local_admins leaks name", `[{"type":"max_local_admins","count":1,"name":"x"}]`},
		{"forbidden_software leaks count", `[{"type":"forbidden_software","name":"x","count":1}]`},
		{"required_software leaks volumes", `[{"type":"required_software","name":"x","volumes":"all"}]`},
		{"profile_applied leaks name", `[{"type":"profile_applied","profile_id":"` + uuid.Must(uuid.NewV7()).String() + `","name":"x"}]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := compliance.ParseRules([]byte(tc.raw))
			if err == nil {
				t.Fatalf("expected an error, got none")
			}
			if !errors.Is(err, compliance.ErrBadRules) {
				t.Fatalf("expected error to wrap ErrBadRules, got %v", err)
			}
		})
	}
}

// TestParseRulesLeakedFieldNamesTypeAndField checks the exact wording the
// review asked for, on top of the generic rejection covered above.
func TestParseRulesLeakedFieldNamesTypeAndField(t *testing.T) {
	_, err := compliance.ParseRules([]byte(`[{"type":"no_pending_reboot","hours":999}]`))
	if err == nil || !errors.Is(err, compliance.ErrBadRules) {
		t.Fatalf("expected an ErrBadRules error, got %v", err)
	}
	if !strings.Contains(err.Error(), `field "hours" does not apply to rule type "no_pending_reboot"`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestParseRulesMaxLocalAdminsZeroCount checks that an explicit 0 - a
// meaningful value distinct from the field being absent - is accepted, since
// the per-type field check must not confuse "present but zero" with "absent".
func TestParseRulesMaxLocalAdminsZeroCount(t *testing.T) {
	rules := mustParse(t, `[{"type":"max_local_admins","count":0}]`)
	if len(rules) != 1 || rules[0].Count != 0 {
		t.Fatalf("got %+v, want one rule with count 0", rules)
	}
	now := time.Now()
	noAdmins := compliance.Evaluate(rules, compliance.Facts{Inventory: &protocol.Inventory{}}, now)
	if noAdmins.State != compliance.StateCompliant {
		t.Fatalf("zero admins against count:0: got %v, want compliant", noAdmins)
	}
	oneAdmin := compliance.Evaluate(rules, compliance.Facts{Inventory: &protocol.Inventory{LocalAdmins: []string{"a"}}}, now)
	if oneAdmin.State != compliance.StateNonCompliant {
		t.Fatalf("one admin against count:0: got %v, want non_compliant", oneAdmin)
	}
}

func TestParseRulesAccepts50(t *testing.T) {
	raw := "[" + strings.TrimSuffix(strings.Repeat(`{"type":"no_pending_reboot"},`, 50), ",") + "]"
	rules, err := compliance.ParseRules([]byte(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 50 {
		t.Fatalf("got %d rules, want 50", len(rules))
	}
}

func TestMarshalRulesRoundTrip(t *testing.T) {
	pid := uuid.Must(uuid.NewV7())
	rules := mustParse(t, `[
		{"type":"os_build_min","build":"26100"},
		{"type":"agent_version_min","version":"1.2.3"},
		{"type":"bitlocker","volumes":"system"},
		{"type":"tpm","min_version":"2.0"},
		{"type":"checked_in_within","hours":168},
		{"type":"inventory_within","hours":24},
		{"type":"updates_within","days":30},
		{"type":"no_pending_reboot"},
		{"type":"max_local_admins","count":2},
		{"type":"forbidden_software","name":"uTorrent"},
		{"type":"required_software","name":"CrowdStrike"},
		{"type":"profile_applied","profile_id":"`+pid.String()+`"}
	]`)
	raw, err := compliance.MarshalRules(rules)
	if err != nil {
		t.Fatalf("MarshalRules: %v", err)
	}
	back, err := compliance.ParseRules(raw)
	if err != nil {
		t.Fatalf("re-parsing marshalled rules: %v", err)
	}
	if len(back) != len(rules) {
		t.Fatalf("got %d rules back, want %d", len(back), len(rules))
	}
	raw2, err := compliance.MarshalRules(back)
	if err != nil {
		t.Fatalf("MarshalRules (2nd pass): %v", err)
	}
	if string(raw) != string(raw2) {
		t.Fatalf("marshalling is not canonical:\n%s\nvs\n%s", raw, raw2)
	}
}

func TestEvaluateOSBuildMin(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	rules := mustParse(t, `[{"type":"os_build_min","build":"26100"}]`)

	compliant := compliance.Evaluate(rules, compliance.Facts{Device: store.Device{OSBuild: "26100.2033"}}, now)
	if compliant.State != compliance.StateCompliant {
		t.Fatalf("above minimum: got %v, want compliant", compliant)
	}

	boundary := compliance.Evaluate(rules, compliance.Facts{Device: store.Device{OSBuild: "26100"}}, now)
	if boundary.State != compliance.StateCompliant {
		t.Fatalf("exact boundary: got %v, want compliant", boundary)
	}

	nonCompliant := compliance.Evaluate(rules, compliance.Facts{Device: store.Device{OSBuild: "22631"}}, now)
	if nonCompliant.State != compliance.StateNonCompliant {
		t.Fatalf("below minimum: got %v, want non_compliant", nonCompliant)
	}
	if len(nonCompliant.Failures) != 1 || nonCompliant.Failures[0].Detail != "the OS build is 22631, below the required 26100" {
		t.Fatalf("unexpected failure: %+v", nonCompliant.Failures)
	}

	unknown := compliance.Evaluate(rules, compliance.Facts{Device: store.Device{OSBuild: ""}}, now)
	if unknown.State != compliance.StateUnknown {
		t.Fatalf("no build: got %v, want unknown", unknown)
	}
	if unknown.Failures[0].Detail != "the device has not reported an OS build" {
		t.Fatalf("unexpected detail: %q", unknown.Failures[0].Detail)
	}
}

func TestEvaluateAgentVersionMin(t *testing.T) {
	now := time.Now()
	rules := mustParse(t, `[{"type":"agent_version_min","version":"2.5.0"}]`)

	if got := compliance.Evaluate(rules, compliance.Facts{Device: store.Device{AgentVersion: "2.6.0"}}, now); got.State != compliance.StateCompliant {
		t.Fatalf("above: got %v", got)
	}
	if got := compliance.Evaluate(rules, compliance.Facts{Device: store.Device{AgentVersion: "2.5.0"}}, now); got.State != compliance.StateCompliant {
		t.Fatalf("boundary: got %v", got)
	}
	if got := compliance.Evaluate(rules, compliance.Facts{Device: store.Device{AgentVersion: "2.4.9"}}, now); got.State != compliance.StateNonCompliant {
		t.Fatalf("below: got %v", got)
	} else if got.Failures[0].Detail != "the agent version is 2.4.9, below the required 2.5.0" {
		t.Fatalf("unexpected detail: %q", got.Failures[0].Detail)
	}
	if got := compliance.Evaluate(rules, compliance.Facts{Device: store.Device{AgentVersion: ""}}, now); got.State != compliance.StateUnknown {
		t.Fatalf("empty: got %v", got)
	} else if got.Failures[0].Detail != "the agent version is not reported" {
		t.Fatalf("unexpected detail: %q", got.Failures[0].Detail)
	}
	if got := compliance.Evaluate(rules, compliance.Facts{Device: store.Device{AgentVersion: "nightly"}}, now); got.State != compliance.StateUnknown {
		t.Fatalf("non-dotted: got %v", got)
	} else if got.Failures[0].Detail != `the agent version "nightly" is not a dotted version number` {
		t.Fatalf("unexpected detail: %q", got.Failures[0].Detail)
	}
}

func TestEvaluateBitLockerSystem(t *testing.T) {
	now := time.Now()
	rules := mustParse(t, `[{"type":"bitlocker","volumes":"system"}]`)

	on := &protocol.Inventory{Disks: []protocol.Disk{{Name: "C:", BitLocker: "on"}}}
	if got := compliance.Evaluate(rules, compliance.Facts{Inventory: on}, now); got.State != compliance.StateCompliant {
		t.Fatalf("on: got %v", got)
	}

	// Boundary: tolerate a trailing backslash and different case.
	boundary := &protocol.Inventory{Disks: []protocol.Disk{{Name: `c:\`, BitLocker: "on"}}}
	if got := compliance.Evaluate(rules, compliance.Facts{Inventory: boundary}, now); got.State != compliance.StateCompliant {
		t.Fatalf("boundary name form: got %v", got)
	}

	off := &protocol.Inventory{Disks: []protocol.Disk{{Name: "C:", BitLocker: "off"}}}
	got := compliance.Evaluate(rules, compliance.Facts{Inventory: off}, now)
	if got.State != compliance.StateNonCompliant {
		t.Fatalf("off: got %v", got)
	}
	if got.Failures[0].Detail != "BitLocker is off on C:" {
		t.Fatalf("unexpected detail: %q", got.Failures[0].Detail)
	}

	unknownVol := &protocol.Inventory{Disks: []protocol.Disk{{Name: "C:", BitLocker: "unknown"}}}
	if got := compliance.Evaluate(rules, compliance.Facts{Inventory: unknownVol}, now); got.State != compliance.StateUnknown {
		t.Fatalf("unknown status: got %v", got)
	} else if got.Failures[0].Detail != "BitLocker status is unknown for C:" {
		t.Fatalf("unexpected detail: %q", got.Failures[0].Detail)
	}

	noVol := &protocol.Inventory{Disks: []protocol.Disk{{Name: "D:", BitLocker: "on"}}}
	if got := compliance.Evaluate(rules, compliance.Facts{Inventory: noVol}, now); got.State != compliance.StateUnknown {
		t.Fatalf("no system volume: got %v", got)
	} else if got.Failures[0].Detail != "no system volume was reported" {
		t.Fatalf("unexpected detail: %q", got.Failures[0].Detail)
	}

	if got := compliance.Evaluate(rules, compliance.Facts{Inventory: nil}, now); got.State != compliance.StateUnknown {
		t.Fatalf("no inventory: got %v", got)
	} else if got.Failures[0].Detail != "no inventory has been received" {
		t.Fatalf("unexpected detail: %q", got.Failures[0].Detail)
	}
}

func TestEvaluateBitLockerAll(t *testing.T) {
	now := time.Now()
	rules := mustParse(t, `[{"type":"bitlocker","volumes":"all"}]`)

	allOn := &protocol.Inventory{Disks: []protocol.Disk{{Name: "C:", BitLocker: "on"}, {Name: "D:", BitLocker: "on"}}}
	if got := compliance.Evaluate(rules, compliance.Facts{Inventory: allOn}, now); got.State != compliance.StateCompliant {
		t.Fatalf("boundary all-on multi-disk: got %v", got)
	}

	oneOff := &protocol.Inventory{Disks: []protocol.Disk{{Name: "C:", BitLocker: "on"}, {Name: "D:", BitLocker: "off"}}}
	if got := compliance.Evaluate(rules, compliance.Facts{Inventory: oneOff}, now); got.State != compliance.StateNonCompliant {
		t.Fatalf("one off: got %v", got)
	} else if got.Failures[0].Detail != "BitLocker is off on D:" {
		t.Fatalf("unexpected detail: %q", got.Failures[0].Detail)
	}

	oneUnknown := &protocol.Inventory{Disks: []protocol.Disk{{Name: "C:", BitLocker: "on"}, {Name: "D:", BitLocker: "unknown"}}}
	if got := compliance.Evaluate(rules, compliance.Facts{Inventory: oneUnknown}, now); got.State != compliance.StateUnknown {
		t.Fatalf("one unknown: got %v", got)
	} else if got.Failures[0].Detail != "BitLocker status is unknown for D:" {
		t.Fatalf("unexpected detail: %q", got.Failures[0].Detail)
	}

	noDisks := &protocol.Inventory{}
	if got := compliance.Evaluate(rules, compliance.Facts{Inventory: noDisks}, now); got.State != compliance.StateUnknown {
		t.Fatalf("no fixed volumes reported: got %v, want unknown", got)
	} else if got.Failures[0].Detail != "the device reported no fixed volumes" {
		t.Fatalf("unexpected detail: %q", got.Failures[0].Detail)
	}

	if got := compliance.Evaluate(rules, compliance.Facts{Inventory: nil}, now); got.State != compliance.StateUnknown {
		t.Fatalf("no inventory: got %v", got)
	} else if got.Failures[0].Detail != "no inventory has been received" {
		t.Fatalf("unexpected detail: %q", got.Failures[0].Detail)
	}
}

func TestEvaluateTPM(t *testing.T) {
	now := time.Now()

	presence := mustParse(t, `[{"type":"tpm"}]`)
	present := &protocol.Inventory{Hardware: protocol.Hardware{TPMPresent: true}}
	if got := compliance.Evaluate(presence, compliance.Facts{Inventory: present}, now); got.State != compliance.StateCompliant {
		t.Fatalf("present, no min: got %v", got)
	}
	absent := &protocol.Inventory{Hardware: protocol.Hardware{TPMPresent: false}}
	if got := compliance.Evaluate(presence, compliance.Facts{Inventory: absent}, now); got.State != compliance.StateNonCompliant {
		t.Fatalf("absent: got %v", got)
	} else if got.Failures[0].Detail != "no TPM is present" {
		t.Fatalf("unexpected detail: %q", got.Failures[0].Detail)
	}
	if got := compliance.Evaluate(presence, compliance.Facts{Inventory: nil}, now); got.State != compliance.StateUnknown {
		t.Fatalf("no inventory: got %v", got)
	} else if got.Failures[0].Detail != "no inventory has been received" {
		t.Fatalf("unexpected detail: %q", got.Failures[0].Detail)
	}

	versioned := mustParse(t, `[{"type":"tpm","min_version":"2.0"}]`)
	above := &protocol.Inventory{Hardware: protocol.Hardware{TPMPresent: true, TPMVersion: "2.1"}}
	if got := compliance.Evaluate(versioned, compliance.Facts{Inventory: above}, now); got.State != compliance.StateCompliant {
		t.Fatalf("above min version: got %v", got)
	}
	boundary := &protocol.Inventory{Hardware: protocol.Hardware{TPMPresent: true, TPMVersion: "2.0"}}
	if got := compliance.Evaluate(versioned, compliance.Facts{Inventory: boundary}, now); got.State != compliance.StateCompliant {
		t.Fatalf("boundary version: got %v", got)
	}
	below := &protocol.Inventory{Hardware: protocol.Hardware{TPMPresent: true, TPMVersion: "1.2"}}
	if got := compliance.Evaluate(versioned, compliance.Facts{Inventory: below}, now); got.State != compliance.StateNonCompliant {
		t.Fatalf("below min version: got %v", got)
	} else if got.Failures[0].Detail != "the TPM version is 1.2, below the required 2.0" {
		t.Fatalf("unexpected detail: %q", got.Failures[0].Detail)
	}
}

func TestEvaluateCheckedInWithin(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	rules := mustParse(t, `[{"type":"checked_in_within","hours":168}]`)

	recent := compliance.Facts{Device: store.Device{LastSeenAt: ts(1, now)}}
	if got := compliance.Evaluate(rules, recent, now); got.State != compliance.StateCompliant {
		t.Fatalf("recent: got %v", got)
	}

	boundary := compliance.Facts{Device: store.Device{LastSeenAt: ts(168, now)}}
	if got := compliance.Evaluate(rules, boundary, now); got.State != compliance.StateCompliant {
		t.Fatalf("exact boundary: got %v", got)
	}

	stale := compliance.Facts{Device: store.Device{LastSeenAt: ts(216, now)}} // 9 days
	got := compliance.Evaluate(rules, stale, now)
	if got.State != compliance.StateNonCompliant {
		t.Fatalf("stale: got %v", got)
	}
	if got.Failures[0].Detail != "last check-in was 9 days ago (limit 168 hours)" {
		t.Fatalf("unexpected detail: %q", got.Failures[0].Detail)
	}

	if got := compliance.Evaluate(rules, compliance.Facts{Device: store.Device{}}, now); got.State != compliance.StateUnknown {
		t.Fatalf("never seen: got %v", got)
	} else if got.Failures[0].Detail != "the device has never checked in" {
		t.Fatalf("unexpected detail: %q", got.Failures[0].Detail)
	}
}

func TestEvaluateInventoryWithin(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	rules := mustParse(t, `[{"type":"inventory_within","hours":24}]`)

	recent := ts(1, now)
	if got := compliance.Evaluate(rules, compliance.Facts{InventoryReceivedAt: recent}, now); got.State != compliance.StateCompliant {
		t.Fatalf("recent: got %v", got)
	}
	boundary := ts(24, now)
	if got := compliance.Evaluate(rules, compliance.Facts{InventoryReceivedAt: boundary}, now); got.State != compliance.StateCompliant {
		t.Fatalf("boundary: got %v", got)
	}
	stale := ts(48, now)
	if got := compliance.Evaluate(rules, compliance.Facts{InventoryReceivedAt: stale}, now); got.State != compliance.StateNonCompliant {
		t.Fatalf("stale: got %v", got)
	} else if got.Failures[0].Detail != "inventory was last received 2 days ago (limit 24 hours)" {
		t.Fatalf("unexpected detail: %q", got.Failures[0].Detail)
	}
	if got := compliance.Evaluate(rules, compliance.Facts{InventoryReceivedAt: nil}, now); got.State != compliance.StateUnknown {
		t.Fatalf("never: got %v", got)
	} else if got.Failures[0].Detail != "inventory has never been received" {
		t.Fatalf("unexpected detail: %q", got.Failures[0].Detail)
	}
}

func TestEvaluateUpdatesWithin(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	rules := mustParse(t, `[{"type":"updates_within","days":30}]`)

	recent := ts(24, now) // 1 day
	if got := compliance.Evaluate(rules, compliance.Facts{Inventory: &protocol.Inventory{LastUpdateInstalledAt: recent}}, now); got.State != compliance.StateCompliant {
		t.Fatalf("recent: got %v", got)
	}
	boundary := ts(30*24, now)
	if got := compliance.Evaluate(rules, compliance.Facts{Inventory: &protocol.Inventory{LastUpdateInstalledAt: boundary}}, now); got.State != compliance.StateCompliant {
		t.Fatalf("boundary: got %v", got)
	}
	stale := ts(45*24, now)
	got := compliance.Evaluate(rules, compliance.Facts{Inventory: &protocol.Inventory{LastUpdateInstalledAt: stale}}, now)
	if got.State != compliance.StateNonCompliant {
		t.Fatalf("stale: got %v", got)
	}
	if got.Failures[0].Detail != "the last update was installed 45 days ago (limit 30 days)" {
		t.Fatalf("unexpected detail: %q", got.Failures[0].Detail)
	}
	if got := compliance.Evaluate(rules, compliance.Facts{Inventory: &protocol.Inventory{}}, now); got.State != compliance.StateUnknown {
		t.Fatalf("no date: got %v", got)
	} else if got.Failures[0].Detail != "no update installation date has been reported" {
		t.Fatalf("unexpected detail: %q", got.Failures[0].Detail)
	}
	if got := compliance.Evaluate(rules, compliance.Facts{Inventory: nil}, now); got.State != compliance.StateUnknown {
		t.Fatalf("no inventory: got %v", got)
	} else if got.Failures[0].Detail != "no update installation date has been reported" {
		t.Fatalf("unexpected detail: %q", got.Failures[0].Detail)
	}
}

func TestEvaluateNoPendingReboot(t *testing.T) {
	now := time.Now()
	rules := mustParse(t, `[{"type":"no_pending_reboot"}]`)

	if got := compliance.Evaluate(rules, compliance.Facts{Inventory: &protocol.Inventory{PendingReboot: false}}, now); got.State != compliance.StateCompliant {
		t.Fatalf("clean: got %v", got)
	}
	got := compliance.Evaluate(rules, compliance.Facts{Inventory: &protocol.Inventory{PendingReboot: true}}, now)
	if got.State != compliance.StateNonCompliant {
		t.Fatalf("pending: got %v", got)
	}
	if got.Failures[0].Detail != "a reboot is pending" {
		t.Fatalf("unexpected detail: %q", got.Failures[0].Detail)
	}
	if got := compliance.Evaluate(rules, compliance.Facts{Inventory: nil}, now); got.State != compliance.StateUnknown {
		t.Fatalf("no inventory: got %v", got)
	} else if got.Failures[0].Detail != "no inventory has been received" {
		t.Fatalf("unexpected detail: %q", got.Failures[0].Detail)
	}
}

func TestEvaluateMaxLocalAdmins(t *testing.T) {
	now := time.Now()
	rules := mustParse(t, `[{"type":"max_local_admins","count":2}]`)

	one := &protocol.Inventory{LocalAdmins: []string{"Administrator"}}
	if got := compliance.Evaluate(rules, compliance.Facts{Inventory: one}, now); got.State != compliance.StateCompliant {
		t.Fatalf("below: got %v", got)
	}
	boundary := &protocol.Inventory{LocalAdmins: []string{"a", "b"}}
	if got := compliance.Evaluate(rules, compliance.Facts{Inventory: boundary}, now); got.State != compliance.StateCompliant {
		t.Fatalf("exact boundary: got %v", got)
	}
	over := &protocol.Inventory{LocalAdmins: []string{"a", "b", "c"}}
	got := compliance.Evaluate(rules, compliance.Facts{Inventory: over}, now)
	if got.State != compliance.StateNonCompliant {
		t.Fatalf("over: got %v", got)
	}
	if got.Failures[0].Detail != "there are 3 local admins, above the limit of 2" {
		t.Fatalf("unexpected detail: %q", got.Failures[0].Detail)
	}
	if got := compliance.Evaluate(rules, compliance.Facts{Inventory: nil}, now); got.State != compliance.StateUnknown {
		t.Fatalf("no inventory: got %v", got)
	} else if got.Failures[0].Detail != "no inventory has been received" {
		t.Fatalf("unexpected detail: %q", got.Failures[0].Detail)
	}
}

func TestEvaluateForbiddenSoftware(t *testing.T) {
	now := time.Now()
	rules := mustParse(t, `[{"type":"forbidden_software","name":"utorrent"}]`)

	clean := &protocol.Inventory{Software: []protocol.Software{{Name: "7-Zip"}}}
	if got := compliance.Evaluate(rules, compliance.Facts{Inventory: clean}, now); got.State != compliance.StateCompliant {
		t.Fatalf("clean: got %v", got)
	}
	// Boundary: case-insensitive substring match.
	found := &protocol.Inventory{Software: []protocol.Software{{Name: "uTorrent 3.6"}}}
	got := compliance.Evaluate(rules, compliance.Facts{Inventory: found}, now)
	if got.State != compliance.StateNonCompliant {
		t.Fatalf("forbidden present: got %v", got)
	}
	if got.Failures[0].Detail != `forbidden software "uTorrent 3.6" is installed` {
		t.Fatalf("unexpected detail: %q", got.Failures[0].Detail)
	}
	if got := compliance.Evaluate(rules, compliance.Facts{Inventory: nil}, now); got.State != compliance.StateUnknown {
		t.Fatalf("no inventory: got %v", got)
	} else if got.Failures[0].Detail != "no inventory has been received" {
		t.Fatalf("unexpected detail: %q", got.Failures[0].Detail)
	}
}

func TestEvaluateRequiredSoftware(t *testing.T) {
	now := time.Now()
	rules := mustParse(t, `[{"type":"required_software","name":"crowdstrike"}]`)

	present := &protocol.Inventory{Software: []protocol.Software{{Name: "CrowdStrike Falcon Sensor"}}}
	if got := compliance.Evaluate(rules, compliance.Facts{Inventory: present}, now); got.State != compliance.StateCompliant {
		t.Fatalf("present (boundary case-insensitive substring): got %v", got)
	}
	missing := &protocol.Inventory{Software: []protocol.Software{{Name: "7-Zip"}}}
	got := compliance.Evaluate(rules, compliance.Facts{Inventory: missing}, now)
	if got.State != compliance.StateNonCompliant {
		t.Fatalf("missing: got %v", got)
	}
	if got.Failures[0].Detail != `required software matching "crowdstrike" is not installed` {
		t.Fatalf("unexpected detail: %q", got.Failures[0].Detail)
	}
	if got := compliance.Evaluate(rules, compliance.Facts{Inventory: nil}, now); got.State != compliance.StateUnknown {
		t.Fatalf("no inventory: got %v", got)
	} else if got.Failures[0].Detail != "no inventory has been received" {
		t.Fatalf("unexpected detail: %q", got.Failures[0].Detail)
	}
}

func TestEvaluateProfileApplied(t *testing.T) {
	now := time.Now()
	pid := uuid.Must(uuid.NewV7())
	other := uuid.Must(uuid.NewV7())
	rules := mustParse(t, `[{"type":"profile_applied","profile_id":"`+pid.String()+`"}]`)

	// Boundary: the map holds another profile's status too; lookup must pick the right key.
	succeeded := map[uuid.UUID]string{pid: store.ItemSucceeded, other: store.ItemFailed}
	if got := compliance.Evaluate(rules, compliance.Facts{ProfileStatus: succeeded}, now); got.State != compliance.StateCompliant {
		t.Fatalf("succeeded: got %v", got)
	}

	failed := map[uuid.UUID]string{pid: store.ItemFailed}
	got := compliance.Evaluate(rules, compliance.Facts{ProfileStatus: failed}, now)
	if got.State != compliance.StateNonCompliant {
		t.Fatalf("failed: got %v", got)
	}
	if got.Failures[0].Detail != "the profile's status is failed, not succeeded" {
		t.Fatalf("unexpected detail: %q", got.Failures[0].Detail)
	}

	pending := map[uuid.UUID]string{pid: store.ItemPending}
	if got := compliance.Evaluate(rules, compliance.Facts{ProfileStatus: pending}, now); got.State != compliance.StateUnknown {
		t.Fatalf("pending: got %v", got)
	} else if got.Failures[0].Detail != "the profile has not finished applying" {
		t.Fatalf("unexpected detail: %q", got.Failures[0].Detail)
	}

	if got := compliance.Evaluate(rules, compliance.Facts{ProfileStatus: nil}, now); got.State != compliance.StateUnknown {
		t.Fatalf("no status row: got %v", got)
	} else if got.Failures[0].Detail != "the profile has not finished applying" {
		t.Fatalf("unexpected detail: %q", got.Failures[0].Detail)
	}
}

func TestEvaluateOrderAndOverallState(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	rules := mustParse(t, `[
		{"type":"no_pending_reboot"},
		{"type":"tpm"},
		{"type":"os_build_min","build":"26100"}
	]`)
	facts := compliance.Facts{
		Device:    store.Device{OSBuild: "22631"},
		Inventory: &protocol.Inventory{PendingReboot: true},
	}
	got := compliance.Evaluate(rules, facts, now)
	if got.State != compliance.StateNonCompliant {
		t.Fatalf("got %v, want non_compliant", got)
	}
	if len(got.Failures) != 3 {
		t.Fatalf("got %d failures, want 3: %+v", len(got.Failures), got.Failures)
	}
	// Deterministic: failures appear in rule order, not grouped by state.
	if got.Failures[0].Rule != "no_pending_reboot" || got.Failures[1].Rule != "tpm" || got.Failures[2].Rule != "os_build_min" {
		t.Fatalf("failures out of order: %+v", got.Failures)
	}
	if got.Failures[0].State != compliance.StateNonCompliant || got.Failures[2].State != compliance.StateNonCompliant {
		t.Fatalf("unexpected states: %+v", got.Failures)
	}
	// unknown alone (no non_compliant) yields overall unknown
	unknownOnly := mustParse(t, `[{"type":"tpm"}]`)
	if got := compliance.Evaluate(unknownOnly, compliance.Facts{Inventory: nil}, now); got.State != compliance.StateUnknown {
		t.Fatalf("unknown-only: got %v", got)
	}
	if got := compliance.Evaluate(nil, compliance.Facts{}, now); got.State != compliance.StateCompliant {
		t.Fatalf("no rules: got %v", got)
	}
}

func TestCompareDotted(t *testing.T) {
	cases := []struct {
		a, b string
		want int
		ok   bool
	}{
		{"26100", "26100", 0, true},
		{"26100.2033", "26100", 1, true},
		{"26100", "26100.1", -1, true},
		{"1.2.3", "1.10.0", -1, true},
		{"2.0", "10.0", -1, true},
		{"", "1.0", 0, false},
		{"abc", "1.0", 0, false},
		{"1.0", "1.0.0", 0, true},
	}
	for _, tc := range cases {
		got, ok := compliance.CompareDotted(tc.a, tc.b)
		if ok != tc.ok {
			t.Fatalf("CompareDotted(%q,%q): ok = %v, want %v", tc.a, tc.b, ok, tc.ok)
		}
		if ok && (got < 0) != (tc.want < 0) || (got > 0) != (tc.want > 0) {
			t.Fatalf("CompareDotted(%q,%q) = %d, want sign of %d", tc.a, tc.b, got, tc.want)
		}
	}
}
