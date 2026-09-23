package compliance_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"retune/internal/protocol"
	"retune/internal/server/compliance"
)

func patched(build string, ubr *int) compliance.Facts {
	return compliance.Facts{Inventory: &protocol.Inventory{OS: protocol.OSInfo{Build: build, UBR: ubr}}}
}

func ubr(n int) *int { return &n }

func TestEvaluateOSBuildMinPerRelease(t *testing.T) {
	now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	rules := mustParse(t, `[{"type":"os_build_min_per_release","minimums":{"26100":"26100.2605","22631":"22631.4751"}}]`)

	cases := []struct {
		name   string
		facts  compliance.Facts
		state  string
		detail string
	}{
		{"patched 24H2", patched("26100", ubr(2894)), compliance.StateCompliant, ""},
		{"exactly the minimum", patched("26100", ubr(2605)), compliance.StateCompliant, ""},
		// 2605 vs 999: compared as numbers, not text.
		{"behind on 24H2", patched("26100", ubr(999)), compliance.StateNonCompliant,
			"the OS build is 26100.999, below the required 26100.2605"},
		{"patched 23H2", patched("22631", ubr(4751)), compliance.StateCompliant, ""},
		{"a release not listed", patched("19045", ubr(5000)), compliance.StateUnknown,
			"no minimum is set for build 19045 (the device is at 19045.5000)"},
		{"an old agent", patched("26100", nil), compliance.StateUnknown,
			"the device has not reported its patch level; its agent may predate this rule"},
		{"no inventory", compliance.Facts{}, compliance.StateUnknown, "the device has not reported an OS build"},
	}
	for _, c := range cases {
		got := compliance.Evaluate(rules, c.facts, now)
		if got.State != c.state {
			t.Errorf("%s: state = %s, want %s (%+v)", c.name, got.State, c.state, got.Failures)
			continue
		}
		if c.detail != "" && (len(got.Failures) != 1 || got.Failures[0].Detail != c.detail) {
			t.Errorf("%s: failures = %+v, want %q", c.name, got.Failures, c.detail)
		}
	}
}

func TestParseOSBuildMinPerRelease(t *testing.T) {
	rules := mustParse(t, `[{"type":"os_build_min_per_release","minimums":{"26100":"26100.2605"}}]`)
	out, err := compliance.MarshalRules(rules)
	if err != nil {
		t.Fatal(err)
	}
	var back []map[string]any
	if err := json.Unmarshal(out, &back); err != nil || back[0]["minimums"] == nil {
		t.Fatalf("round trip = %s, %v", out, err)
	}

	bad := map[string]string{
		"no minimums":           `[{"type":"os_build_min_per_release"}]`,
		"empty minimums":        `[{"type":"os_build_min_per_release","minimums":{}}]`,
		"not a map":             `[{"type":"os_build_min_per_release","minimums":["26100.2605"]}]`,
		"minimum for the wrong": `[{"type":"os_build_min_per_release","minimums":{"26100":"22631.4751"}}]`,
		"no patch level":        `[{"type":"os_build_min_per_release","minimums":{"26100":"26100"}}]`,
		"a dotted base":         `[{"type":"os_build_min_per_release","minimums":{"26100.1":"26100.1.5"}}]`,
		"text":                  `[{"type":"os_build_min_per_release","minimums":{"24H2":"24H2.1"}}]`,
		"a field of another":    `[{"type":"os_build_min_per_release","minimums":{"26100":"26100.1"},"build":"1"}]`,
	}
	for name, raw := range bad {
		if _, err := compliance.ParseRules([]byte(raw)); !errors.Is(err, compliance.ErrBadRules) {
			t.Errorf("%s: err = %v, want ErrBadRules", name, err)
		}
	}
	many := map[string]string{}
	for i := 0; i < 21; i++ {
		base := strings.Repeat("1", 5) + string(rune('0'+i%10)) + string(rune('0'+i/10))
		many[base] = base + ".1"
	}
	raw, _ := json.Marshal([]map[string]any{{"type": "os_build_min_per_release", "minimums": many}})
	if _, err := compliance.ParseRules(raw); !errors.Is(err, compliance.ErrBadRules) {
		t.Errorf("21 releases: err = %v", err)
	}
}
