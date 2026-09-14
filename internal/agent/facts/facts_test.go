package facts_test

import (
	"testing"

	"retune/internal/agent/facts"
)

// A build whose version was never injected must not self-update. It would
// report the placeholder after updating, be told to update again, and do that
// on every check-in on every machine for as long as the assignment stood.
func TestVersionInjectedGuardsTheDefault(t *testing.T) {
	if facts.PlaceholderVersion == "" {
		t.Fatal("the placeholder must be a real string, or the guard cannot recognise it")
	}
	if facts.AgentVersion == facts.PlaceholderVersion && facts.VersionInjected() {
		t.Error("an uninjected build must report its version as not injected")
	}
}

// Checkin reports whatever the build was stamped with.
func TestCheckinCarriesTheVersion(t *testing.T) {
	if got := facts.Checkin().AgentVersion; got != facts.AgentVersion {
		t.Errorf("check-in reported %q, want %q", got, facts.AgentVersion)
	}
}
