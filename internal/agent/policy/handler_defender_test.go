package policy_test

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"retune/internal/agent/policy"
	"retune/internal/protocol"
)

// fakeDefender stands in for the Defender cmdlets: it answers
// Get-MpPreference from its own state and applies Set-MpPreference to it,
// unless tamper is on, in which case - like Tamper Protection - the command
// succeeds and nothing changes.
type fakeDefender struct {
	prefs  map[string]any
	tamper bool
	sets   []string
}

func newFakeDefender() *fakeDefender {
	return &fakeDefender{prefs: map[string]any{
		"DisableRealtimeMonitoring": false, "MAPSReporting": 2, "SubmitSamplesConsent": 1,
		"PUAProtection": 0, "CloudBlockLevel": 0,
	}}
}

func (f *fakeDefender) run(_ context.Context, script string) (string, error) {
	switch {
	case strings.HasPrefix(script, "Get-MpPreference"):
		b, err := json.Marshal(f.prefs)
		return string(b), err
	case strings.HasPrefix(script, "Set-MpPreference"):
		f.sets = append(f.sets, script)
		if f.tamper {
			return "", nil
		}
		fields := strings.Fields(strings.TrimPrefix(script, "Set-MpPreference"))
		for i := 0; i+1 < len(fields); i += 2 {
			name, value := strings.TrimPrefix(fields[i], "-"), fields[i+1]
			switch value {
			case "$true":
				f.prefs[name] = true
			case "$false":
				f.prefs[name] = false
			default:
				n, err := strconv.Atoi(value)
				if err != nil {
					return "", err
				}
				f.prefs[name] = n
			}
		}
		return "", nil
	}
	return "", nil
}

func TestDefenderTestComparesOnlyNamedFields(t *testing.T) {
	f := newFakeDefender()
	h := policy.DefenderHandler{Run: f.run}
	ctx := context.Background()
	// Cloud protection is already advanced; PUA protection is off, but this
	// setting does not mention it, so it has no say.
	ok, err := h.Test(ctx, protocol.Setting{Kind: protocol.KindDefender, CloudProtection: "advanced"})
	if err != nil || !ok {
		t.Fatalf("Test = %v, %v; want true", ok, err)
	}
	ok, err = h.Test(ctx, protocol.Setting{Kind: protocol.KindDefender, PUAProtection: "on"})
	if err != nil || ok {
		t.Fatalf("Test = %v, %v; want false", ok, err)
	}
}

func TestDefenderSetWritesOnlyNamedFields(t *testing.T) {
	f := newFakeDefender()
	h := policy.DefenderHandler{Run: f.run}
	s := protocol.Setting{Kind: protocol.KindDefender, RealtimeMonitoring: boolp(true), PUAProtection: "on", CloudBlockLevel: "high_plus"}
	if err := h.Set(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	if len(f.sets) != 1 {
		t.Fatalf("want one Set-MpPreference, got %q", f.sets)
	}
	want := "Set-MpPreference -CloudBlockLevel 4 -DisableRealtimeMonitoring $false -PUAProtection 1"
	if f.sets[0] != want {
		t.Errorf("command = %q, want %q", f.sets[0], want)
	}
	if strings.Contains(f.sets[0], "MAPSReporting") || strings.Contains(f.sets[0], "SubmitSamplesConsent") {
		t.Error("a field the setting does not name must not be written")
	}
}

// Tamper Protection lets the command succeed and changes nothing. Set must
// not report success it cannot see, and must say what is likely going on.
func TestDefenderSetNoticesTamperProtection(t *testing.T) {
	f := newFakeDefender()
	f.tamper = true
	h := policy.DefenderHandler{Run: f.run}
	err := h.Set(context.Background(), protocol.Setting{Kind: protocol.KindDefender, PUAProtection: "on", RealtimeMonitoring: boolp(true)})
	if err == nil || !strings.Contains(err.Error(), "Tamper Protection") || !strings.Contains(err.Error(), "PUAProtection") {
		t.Fatalf("want an error naming the field and Tamper Protection, got %v", err)
	}
	if strings.Contains(err.Error(), "DisableRealtimeMonitoring") {
		t.Errorf("a field that already matched should not be named: %v", err)
	}
}

func TestDefenderRevertRestoresWhatWasThere(t *testing.T) {
	f := newFakeDefender()
	h := policy.DefenderHandler{Run: f.run}
	ctx := context.Background()
	s := protocol.Setting{Kind: protocol.KindDefender, PUAProtection: "audit", CloudProtection: "off"}

	prior, err := h.Get(ctx, s)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Set(ctx, s); err != nil {
		t.Fatal(err)
	}
	if f.prefs["PUAProtection"] != 2 || f.prefs["MAPSReporting"] != 0 {
		t.Fatalf("after Set: %v", f.prefs)
	}
	f.sets = nil
	if err := h.Revert(ctx, s, prior); err != nil {
		t.Fatal(err)
	}
	if f.prefs["PUAProtection"] != 0 || f.prefs["MAPSReporting"] != 2 {
		t.Errorf("after Revert: %v, want PUA 0 and MAPS 2 back", f.prefs)
	}
	if len(f.sets) != 1 || strings.Contains(f.sets[0], "CloudBlockLevel") {
		t.Errorf("revert should write only the fields the setting named: %q", f.sets)
	}
}

func TestDefenderWithoutPowerShell(t *testing.T) {
	_, err := policy.DefenderHandler{}.Test(context.Background(), protocol.Setting{Kind: protocol.KindDefender, PUAProtection: "on"})
	if err == nil || !strings.Contains(err.Error(), "only supported on Windows") {
		t.Fatalf("want a plain refusal away from Windows, got %v", err)
	}
}
