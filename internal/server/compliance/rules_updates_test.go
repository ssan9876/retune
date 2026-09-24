package compliance_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"retune/internal/protocol"
	"retune/internal/server/compliance"
)

func TestMaxMissingSecurityUpdates(t *testing.T) {
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	rules := mustParse(t, `[{"type":"max_missing_security_updates","count":1}]`)
	for raw, mention := range map[string]string{
		`[{"type":"max_missing_security_updates"}]`:            "count must be between",
		`[{"type":"max_missing_security_updates","count":-1}]`: "count must be between",
		`[{"type":"max_missing_security_updates","days":3}]`:   `field "days" does not apply`,
	} {
		if _, err := compliance.ParseRules([]byte(raw)); !errors.Is(err, compliance.ErrBadRules) || !strings.Contains(err.Error(), mention) {
			t.Errorf("%s: %v", raw, err)
		}
	}
	scan := func(ago time.Duration, errText string, updates ...protocol.PendingUpdate) compliance.Facts {
		return compliance.Facts{Inventory: &protocol.Inventory{WindowsUpdates: &protocol.UpdateStatus{
			ScannedAt: now.Add(-ago), Pending: updates, Error: errText}}}
	}
	sec := func(kb string) protocol.PendingUpdate {
		return protocol.PendingUpdate{Title: kb, KB: kb, Security: true}
	}
	other := protocol.PendingUpdate{Title: "A driver"}

	for name, c := range map[string]struct {
		facts   compliance.Facts
		state   string
		mention string
	}{
		"up to date":          {scan(time.Hour, ""), compliance.StateCompliant, ""},
		"one allowed":         {scan(time.Hour, "", sec("KB1"), other, other), compliance.StateCompliant, ""},
		"two missing":         {scan(time.Hour, "", sec("KB1"), sec("KB2"), other), compliance.StateNonCompliant, "2 security updates are missing (at most 1 allowed): KB1, KB2"},
		"never searched":      {compliance.Facts{Inventory: &protocol.Inventory{}}, compliance.StateUnknown, "has not reported"},
		"no inventory":        {compliance.Facts{}, compliance.StateUnknown, "has not reported"},
		"the search failed":   {scan(time.Hour, "0x8024402C"), compliance.StateUnknown, "0x8024402C"},
		"the search is stale": {scan(8*24*time.Hour, "", sec("KB1"), sec("KB2")), compliance.StateUnknown, "the last Windows Update search was on"},
	} {
		res := compliance.Evaluate(rules, c.facts, now)
		if res.State != c.state {
			t.Errorf("%s: state %s, want %s (%+v)", name, res.State, c.state, res.Failures)
			continue
		}
		if c.mention != "" && (len(res.Failures) != 1 || !strings.Contains(res.Failures[0].Detail, c.mention)) {
			t.Errorf("%s: failures %+v, want mention of %q", name, res.Failures, c.mention)
		}
	}
}
