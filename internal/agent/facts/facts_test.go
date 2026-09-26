package facts_test

import (
	"testing"

	"retune/internal/agent/facts"
	"retune/internal/release"
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

func TestTrustedKeysParsesTheStampedList(t *testing.T) {
	a, _ := release.GenerateKey()
	b, _ := release.GenerateKey()
	saved := facts.TrustedKeysRaw
	t.Cleanup(func() { facts.TrustedKeysRaw = saved })

	facts.TrustedKeysRaw = a.Public().Encode() + "," + b.Public().Encode()
	keys := facts.TrustedKeys()
	if len(keys) != 2 || keys[0].ID() != a.Public().ID() {
		t.Fatalf("parsed %+v", keys)
	}

	facts.TrustedKeysRaw = ""
	if len(facts.TrustedKeys()) != 0 {
		t.Error("an unstamped build trusts nothing")
	}

	// A list that does not parse is treated as empty: a build that trusts
	// fewer keys than intended is safer than one that guesses.
	facts.TrustedKeysRaw = "garbage"
	if len(facts.TrustedKeys()) != 0 {
		t.Error("a malformed list trusts nothing")
	}
}

// Windows 11 still says "Windows 10" in the registry's ProductName; only the
// build tells them apart.
func TestWindowsName(t *testing.T) {
	for _, c := range []struct{ name, build, want string }{
		{"Windows 10 Enterprise Evaluation", "22631", "Windows 11 Enterprise Evaluation (build 22631)"},
		{"Windows 10 Pro", "22000", "Windows 11 Pro (build 22000)"},
		{"Windows 10 Pro", "19045", "Windows 10 Pro (build 19045)"},
		{"Windows Server 2022 Standard", "20348", "Windows Server 2022 Standard (build 20348)"},
		{"Windows Server 2025 Datacenter", "26100", "Windows Server 2025 Datacenter (build 26100)"},
		{"Windows 10 Pro", "", "Windows 10 Pro (build )"},
	} {
		if got := facts.WindowsName(c.name, c.build); got != c.want {
			t.Errorf("WindowsName(%q, %q) = %q, want %q", c.name, c.build, got, c.want)
		}
	}
}
