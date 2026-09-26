package policy_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"retune/internal/agent/policy"
	"retune/internal/opsign"
	"retune/internal/protocol"
	"retune/internal/release"
)

type fakeFetcher struct {
	versions map[int]protocol.ProfileVersionResponse
}

func (f *fakeFetcher) FetchProfile(_ context.Context, _ string, version int) (protocol.ProfileVersionResponse, error) {
	return f.versions[version], nil
}

func profileItem(version int) protocol.Item {
	raw, _ := json.Marshal(protocol.ProfileOptions{RevertOnRemoval: true})
	return protocol.Item{Kind: protocol.ItemKindProfile, ID: "p1", Version: version, Options: raw}
}

// A profile version that isn't signed is held: not applied, and not undone
// either — it is still assigned, and reverting it would change the machine
// on the strength of an unsigned instruction just as surely as applying it.
func TestUnsignedProfileIsHeld(t *testing.T) {
	key, err := release.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	sign := func(settings []protocol.Setting) *opsign.Signature {
		s := opsign.Sign(key, protocol.ProfileManifest(settings))
		return &s
	}
	managed := []protocol.Setting{reg("A", "managed")}
	evil := []protocol.Setting{reg("A", "evil")}
	identity := managed[0].Identity()

	h := newHandler(protocol.KindRegistry)
	h.current[identity] = "original"
	st, rep := newStore(), newReporter()
	f := &fakeFetcher{versions: map[int]protocol.ProfileVersionResponse{
		1: {Version: 1, Settings: managed, Signature: sign(managed)},
		2: {Version: 2, Settings: evil},                           // unsigned
		3: {Version: 3, Settings: evil, Signature: sign(managed)}, // someone else's signature
		4: {Version: 4, Settings: evil, Signature: sign(evil)},
	}}
	s := &policy.Syncer{
		Reconciler: newReconciler(h, st, rep), Fetcher: f,
		Operations: opsign.Policy{Enforced: true, Keys: []release.PublicKey{key.Public()}},
	}
	ctx := context.Background()

	if err := s.Sync(ctx, []protocol.Item{profileItem(1)}); err != nil {
		t.Fatal(err)
	}
	if h.current[identity] != "managed" {
		t.Fatalf("the signed version should apply, got %q", h.current[identity])
	}

	for _, v := range []int{2, 3} {
		if err := s.Sync(ctx, []protocol.Item{profileItem(v)}); err != nil {
			t.Fatal(err)
		}
		if h.current[identity] != "managed" {
			t.Fatalf("version %d: the setting was changed to %q; it should be left as it was", v, h.current[identity])
		}
		got := statusOf(t, rep.reports["p1"], identity)
		if got.Status != protocol.SettingError || !strings.Contains(got.Detail, "refused") {
			t.Errorf("version %d: reported %+v, want an error saying it was refused", v, got)
		}
		if rep.reports["p1"].Version != v {
			t.Errorf("version %d: the report should be for the version held, got %d", v, rep.reports["p1"].Version)
		}
	}

	// Signed properly, it applies.
	if err := s.Sync(ctx, []protocol.Item{profileItem(4)}); err != nil {
		t.Fatal(err)
	}
	if h.current[identity] != "evil" {
		t.Fatalf("the signed version 4 should apply, got %q", h.current[identity])
	}
}

// Held and then unassigned, a profile undoes what its last applied version
// did: the record kept is that version's, not the held one's.
func TestHeldProfileStillRevertsWhenRemoved(t *testing.T) {
	key, err := release.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	managed := []protocol.Setting{reg("A", "managed")}
	sig := opsign.Sign(key, protocol.ProfileManifest(managed))
	identity := managed[0].Identity()

	h := newHandler(protocol.KindRegistry)
	h.current[identity] = "original"
	st, rep := newStore(), newReporter()
	f := &fakeFetcher{versions: map[int]protocol.ProfileVersionResponse{
		1: {Version: 1, Settings: managed, Signature: &sig},
		2: {Version: 2, Settings: []protocol.Setting{reg("B", "x")}},
	}}
	s := &policy.Syncer{
		Reconciler: newReconciler(h, st, rep), Fetcher: f,
		Operations: opsign.Policy{Enforced: true, Keys: []release.PublicKey{key.Public()}},
	}
	ctx := context.Background()
	for _, items := range [][]protocol.Item{{profileItem(1)}, {profileItem(2)}, nil} {
		if err := s.Sync(ctx, items); err != nil {
			t.Fatal(err)
		}
	}
	if h.current[identity] != "original" {
		t.Fatalf("removing the profile should undo version 1, got %q", h.current[identity])
	}
}

// An agent built without operations keys applies what it is sent, as before.
func TestUnsignedProfileAppliesWhenNotEnforced(t *testing.T) {
	settings := []protocol.Setting{reg("A", "managed")}
	h := newHandler(protocol.KindRegistry)
	st, rep := newStore(), newReporter()
	s := &policy.Syncer{
		Reconciler: newReconciler(h, st, rep),
		Fetcher:    &fakeFetcher{versions: map[int]protocol.ProfileVersionResponse{1: {Version: 1, Settings: settings}}},
	}
	if err := s.Sync(context.Background(), []protocol.Item{profileItem(1)}); err != nil {
		t.Fatal(err)
	}
	if h.current[settings[0].Identity()] != "managed" {
		t.Fatalf("got %q", h.current[settings[0].Identity()])
	}
}

// A secret is signed in the clear, as the agent receives it; what the server
// keeps about it is not part of the manifest.
func TestProfileManifestIgnoresSealedForm(t *testing.T) {
	wifi := protocol.Setting{Kind: protocol.KindWiFi, SSID: "Office", Security: "wpa2_personal", Passphrase: "correct horse"}
	sealed := wifi
	sealed.SealedSecret, sealed.SecretSet = &protocol.SealedSecret{Ciphertext: "x", Nonce: "y", MAC: "z"}, true
	if string(protocol.ProfileManifest([]protocol.Setting{wifi})) != string(protocol.ProfileManifest([]protocol.Setting{sealed})) {
		t.Error("the sealed form should not change the manifest")
	}
	other := wifi
	other.Passphrase = "battery staple"
	if string(protocol.ProfileManifest([]protocol.Setting{wifi})) == string(protocol.ProfileManifest([]protocol.Setting{other})) {
		t.Error("a different passphrase must change the manifest")
	}
}
