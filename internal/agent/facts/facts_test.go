package facts_test

import (
	"testing"

	"retune/internal/agent/facts"
	"retune/internal/release"
)

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
