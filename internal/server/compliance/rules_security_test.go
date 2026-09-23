package compliance_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"retune/internal/protocol"
	"retune/internal/server/compliance"
)

func withDefender(d *protocol.DefenderStatus) compliance.Facts {
	return compliance.Facts{Inventory: &protocol.Inventory{Defender: d}}
}

func TestParseSecurityRules(t *testing.T) {
	for _, raw := range []string{
		`[{"type":"defender_realtime"}]`,
		`[{"type":"defender_signatures_within","days":1}]`,
		`[{"type":"defender_signatures_within","days":30}]`,
		`[{"type":"firewall_enabled"}]`,
		`[{"type":"firewall_enabled","profiles":["public","domain"]}]`,
	} {
		mustParse(t, raw)
	}
	for raw, mention := range map[string]string{
		`[{"type":"defender_signatures_within"}]`:            "days must be between 1 and 30",
		`[{"type":"defender_signatures_within","days":31}]`:  "days must be between 1 and 30",
		`[{"type":"defender_realtime","days":3}]`:            `field "days" does not apply`,
		`[{"type":"firewall_enabled","profiles":[]}]`:        "at least one of",
		`[{"type":"firewall_enabled","profiles":["guest"]}]`: `"guest" is not a firewall profile`,
		`[{"type":"firewall_enabled","profiles":"public"}]`:  "list of strings",
	} {
		_, err := compliance.ParseRules([]byte(raw))
		if !errors.Is(err, compliance.ErrBadRules) || !strings.Contains(err.Error(), mention) {
			t.Errorf("%s: want ErrBadRules mentioning %q, got %v", raw, mention, err)
		}
	}
	// Duplicates collapse, and the stored form omits an absent list.
	rules := mustParse(t, `[{"type":"firewall_enabled","profiles":["public","public"]},{"type":"firewall_enabled"}]`)
	b, err := compliance.MarshalRules(rules)
	if err != nil || string(b) != `[{"type":"firewall_enabled","profiles":["public"]},{"type":"firewall_enabled"}]` {
		t.Errorf("stored as %s, %v", b, err)
	}
}

func TestEvaluateDefenderRealtime(t *testing.T) {
	now := time.Now()
	rules := mustParse(t, `[{"type":"defender_realtime"}]`)
	on := &protocol.DefenderStatus{RunningMode: "Normal", AntivirusEnabled: true, RealtimeEnabled: true}

	cases := []struct {
		name   string
		facts  compliance.Facts
		state  string
		detail string
	}{
		{"on", withDefender(on), compliance.StateCompliant, ""},
		{"realtime off", withDefender(&protocol.DefenderStatus{RunningMode: "Normal", AntivirusEnabled: true}),
			compliance.StateNonCompliant, "Defender real-time protection is off"},
		{"antivirus off", withDefender(&protocol.DefenderStatus{RunningMode: "Normal"}),
			compliance.StateNonCompliant, "Defender Antivirus is turned off"},
		{"passive", withDefender(&protocol.DefenderStatus{RunningMode: "Passive Mode"}),
			compliance.StateUnknown, `Defender is in "Passive Mode", so another antivirus is primary`},
		{"not reported", withDefender(nil), compliance.StateUnknown, "Defender status is not reported"},
		{"no inventory", compliance.Facts{}, compliance.StateUnknown, "Defender status is not reported"},
	}
	for _, tc := range cases {
		got := compliance.Evaluate(rules, tc.facts, now)
		if got.State != tc.state {
			t.Errorf("%s: state %s, want %s", tc.name, got.State, tc.state)
			continue
		}
		if tc.detail != "" && got.Failures[0].Detail != tc.detail {
			t.Errorf("%s: detail %q, want %q", tc.name, got.Failures[0].Detail, tc.detail)
		}
	}
}

// Age is measured to the moment of evaluation, so a device that stops
// reporting slides out of compliance on its own.
func TestEvaluateDefenderSignaturesWithin(t *testing.T) {
	now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	rules := mustParse(t, `[{"type":"defender_signatures_within","days":3}]`)
	status := func(hoursAgo float64) compliance.Facts {
		return withDefender(&protocol.DefenderStatus{RunningMode: "Normal", SignatureUpdatedAt: ts(hoursAgo, now)})
	}
	if got := compliance.Evaluate(rules, status(20), now); got.State != compliance.StateCompliant {
		t.Fatalf("fresh: %v", got)
	}
	if got := compliance.Evaluate(rules, status(72), now); got.State != compliance.StateCompliant {
		t.Fatalf("exactly at the limit: %v", got)
	}
	got := compliance.Evaluate(rules, status(24*5), now)
	if got.State != compliance.StateNonCompliant ||
		got.Failures[0].Detail != "Defender signatures were last updated 5 days ago (limit 3 days)" {
		t.Fatalf("stale: %+v", got)
	}
	// The same report, evaluated a week later, is stale on its own.
	if got := compliance.Evaluate(rules, status(20), now.Add(7*24*time.Hour)); got.State != compliance.StateNonCompliant {
		t.Fatalf("a report that has gone old should fail: %v", got)
	}
	if got := compliance.Evaluate(rules, withDefender(&protocol.DefenderStatus{RunningMode: "Normal"}), now); got.State != compliance.StateUnknown {
		t.Fatalf("no update time: %v", got)
	}
}

func TestEvaluateFirewallEnabled(t *testing.T) {
	now := time.Now()
	fw := func(states map[string]bool) compliance.Facts {
		var list []protocol.FirewallProfileState
		for p, on := range states {
			list = append(list, protocol.FirewallProfileState{Profile: p, Enabled: on})
		}
		return compliance.Facts{Inventory: &protocol.Inventory{Firewall: list}}
	}
	all := mustParse(t, `[{"type":"firewall_enabled"}]`)
	publicOnly := mustParse(t, `[{"type":"firewall_enabled","profiles":["public"]}]`)

	if got := compliance.Evaluate(all, fw(map[string]bool{"domain": true, "private": true, "public": true}), now); got.State != compliance.StateCompliant {
		t.Fatalf("all on: %v", got)
	}
	got := compliance.Evaluate(all, fw(map[string]bool{"domain": false, "private": true, "public": false}), now)
	if got.State != compliance.StateNonCompliant || got.Failures[0].Detail != "the firewall is off for: domain, public" {
		t.Fatalf("two off: %+v", got)
	}
	// Only the named profile counts.
	if got := compliance.Evaluate(publicOnly, fw(map[string]bool{"domain": false, "public": true}), now); got.State != compliance.StateCompliant {
		t.Fatalf("public on, domain off, rule names public: %v", got)
	}
	// Off outranks not reported.
	got = compliance.Evaluate(all, fw(map[string]bool{"domain": false}), now)
	if got.State != compliance.StateNonCompliant {
		t.Fatalf("one off, two missing: %v", got)
	}
	got = compliance.Evaluate(all, fw(map[string]bool{"domain": true}), now)
	if got.State != compliance.StateUnknown || got.Failures[0].Detail != "firewall state is not reported for: private, public" {
		t.Fatalf("two missing: %+v", got)
	}
	if got := compliance.Evaluate(all, compliance.Facts{Inventory: &protocol.Inventory{}}, now); got.State != compliance.StateUnknown {
		t.Fatalf("no firewall block: %v", got)
	}
}
