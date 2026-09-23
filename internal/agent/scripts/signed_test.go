package scripts_test

import (
	"context"
	"strings"
	"testing"

	"retune/internal/opsign"
	"retune/internal/protocol"
	"retune/internal/release"
)

func TestSignedScripts(t *testing.T) {
	key, err := release.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	policy := opsign.Policy{Enforced: true, Keys: []release.PublicKey{key.Public()}}
	signed := func(body, detection string) *opsign.Signature {
		s := opsign.Sign(key, opsign.ScriptManifest(body, detection))
		return &s
	}

	cases := map[string]struct {
		version protocol.ScriptVersionResponse
		runs    bool
	}{
		"signed": {protocol.ScriptVersionResponse{Version: 1, Body: "install", Signature: signed("install", "")}, true},
		"signed with detection": {protocol.ScriptVersionResponse{
			Version: 1, Body: "install", DetectionBody: "check", Signature: signed("install", "check"),
		}, true},
		"unsigned": {protocol.ScriptVersionResponse{Version: 1, Body: "install"}, false},
		"body swapped": {protocol.ScriptVersionResponse{
			Version: 1, Body: "format c:", Signature: signed("install", ""),
		}, false},
		// Detection is code too: a signature over the body alone doesn't
		// cover a detection script added beside it.
		"detection added": {protocol.ScriptVersionResponse{
			Version: 1, Body: "install", DetectionBody: "evil", Signature: signed("install", ""),
		}, false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			client := &fakeClient{version: c.version}
			runner := &fakeRunner{exits: map[string]int{"install": 0, "check": 1}}
			s, _ := newScheduler(t, client, runner)
			s.Operations = policy
			if err := s.Sync(context.Background(), []protocol.Item{item("s1", 1, opts(nil))}); err != nil {
				t.Fatal(err)
			}
			if ran := len(runner.ran()) > 0; ran != c.runs {
				t.Fatalf("ran %v, want runs=%v", runner.ran(), c.runs)
			}
			if !c.runs && (len(client.runs) != 1 || client.runs[0].Status != protocol.ResultFailed ||
				!strings.Contains(client.runs[0].Error, "refused")) {
				t.Fatalf("reported %+v", client.runs)
			}
		})
	}

	// Without enforcement, nothing changes.
	client := &fakeClient{version: protocol.ScriptVersionResponse{Version: 1, Body: "install"}}
	runner := &fakeRunner{exits: map[string]int{"install": 0}}
	s, _ := newScheduler(t, client, runner)
	if err := s.Sync(context.Background(), []protocol.Item{item("s1", 1, opts(nil))}); err != nil {
		t.Fatal(err)
	}
	if len(runner.ran()) != 1 {
		t.Fatal("an unsigned script must still run on an agent that doesn't enforce")
	}
}
