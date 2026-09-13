//go:build windows

package policy_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"retune/internal/agent/policy"
	"retune/internal/protocol"
)

// fakeNet stands in for net.exe: it keeps a membership list and records the
// commands it was asked to run.
type fakeNet struct {
	members []string
	ran     []string
}

func (f *fakeNet) run(_ context.Context, name string, args ...string) (string, error) {
	f.ran = append(f.ran, name+" "+strings.Join(args, " "))
	// net localgroup <group>
	if len(args) == 2 {
		var b strings.Builder
		b.WriteString("Alias name     " + args[1] + "\r\n")
		b.WriteString("Comment        Test group\r\n\r\n")
		b.WriteString("Members\r\n\r\n")
		b.WriteString("-------------------------------------------------------------------------------\r\n")
		for _, m := range f.members {
			b.WriteString(m + "\r\n")
		}
		b.WriteString("The command completed successfully.\r\n\r\n")
		return b.String(), nil
	}
	// net localgroup <group> <member> /add|/delete
	if len(args) == 4 {
		member, action := args[2], args[3]
		switch action {
		case "/add":
			f.members = append(f.members, member)
		case "/delete":
			var kept []string
			for _, m := range f.members {
				if !strings.EqualFold(m, member) {
					kept = append(kept, m)
				}
			}
			f.members = kept
		}
		return "The command completed successfully.\r\n", nil
	}
	return "", fmt.Errorf("unexpected command")
}

func groupHandler(f *fakeNet) policy.GroupHandler {
	return policy.GroupHandler{Run: f.run}
}

func TestGroupMembersAreParsed(t *testing.T) {
	f := &fakeNet{members: []string{"Administrator", "CONTOSO\\Ops", "LocalAdmin"}}
	got, err := groupHandler(f).Members(context.Background(), "Administrators")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[1] != "CONTOSO\\Ops" {
		t.Fatalf("members = %v", got)
	}
}

func TestGroupAdditiveAddsWithoutRemoving(t *testing.T) {
	ctx := context.Background()
	f := &fakeNet{members: []string{"Administrator", "Existing"}}
	h := groupHandler(f)
	s := protocol.Setting{
		Kind: protocol.KindGroup, Group: "Administrators",
		Members: []string{"CONTOSO\\Ops"}, Mode: protocol.ModeAdditive,
	}

	if ok, err := h.Test(ctx, s); err != nil || ok {
		t.Fatalf("a missing member is not compliant: ok=%v err=%v", ok, err)
	}
	if err := h.Set(ctx, s); err != nil {
		t.Fatal(err)
	}
	if ok, err := h.Test(ctx, s); err != nil || !ok {
		t.Fatalf("after Set it should be compliant: ok=%v err=%v", ok, err)
	}
	// Nobody was removed.
	if len(f.members) != 3 {
		t.Fatalf("additive mode should not remove anyone, got %v", f.members)
	}
}

// An exact-mode setting must never remove the built-in Administrator, whatever
// the profile says: locking every administrator out is not a configuration a
// management tool should carry out.
func TestGroupExactNeverRemovesTheBuiltInAdministrator(t *testing.T) {
	ctx := context.Background()
	f := &fakeNet{members: []string{"Administrator", "Stale", "CONTOSO\\Ops"}}
	h := groupHandler(f)
	s := protocol.Setting{
		Kind: protocol.KindGroup, Group: "Administrators",
		Members: []string{"CONTOSO\\Ops"}, Mode: protocol.ModeExact,
	}

	if err := h.Set(ctx, s); err != nil {
		t.Fatal(err)
	}
	if containsFold(f.members, "Stale") {
		t.Error("exact mode should have removed the member that is not listed")
	}
	if !containsFold(f.members, "Administrator") {
		t.Fatalf("the built-in Administrator must survive, got %v", f.members)
	}
	// And that state is considered compliant, rather than looping forever
	// trying to remove an account it will never remove.
	if ok, err := h.Test(ctx, s); err != nil || !ok {
		t.Fatalf("it should report compliant: ok=%v err=%v", ok, err)
	}
}

func TestGroupMembersCompareWithoutDomain(t *testing.T) {
	ctx := context.Background()
	f := &fakeNet{members: []string{"Administrator", "Ops"}}
	h := groupHandler(f)
	s := protocol.Setting{
		Kind: protocol.KindGroup, Group: "Administrators",
		Members: []string{"CONTOSO\\Ops"}, Mode: protocol.ModeAdditive,
	}
	ok, err := h.Test(ctx, s)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("CONTOSO\\Ops and Ops are the same member")
	}
}

func TestGroupRevertRestoresTheOriginalMembership(t *testing.T) {
	ctx := context.Background()
	f := &fakeNet{members: []string{"Administrator", "Original"}}
	h := groupHandler(f)
	s := protocol.Setting{
		Kind: protocol.KindGroup, Group: "Administrators",
		Members: []string{"CONTOSO\\Ops"}, Mode: protocol.ModeExact,
	}

	prior, err := h.Get(ctx, s)
	if err != nil || !prior.Exists {
		t.Fatalf("prior = %+v err %v", prior, err)
	}
	if err := h.Set(ctx, s); err != nil {
		t.Fatal(err)
	}
	if containsFold(f.members, "Original") {
		t.Fatal("exact mode should have removed the original member")
	}

	if err := h.Revert(ctx, s, prior); err != nil {
		t.Fatal(err)
	}
	if !containsFold(f.members, "Original") {
		t.Fatalf("revert should restore the original member, got %v", f.members)
	}
	if containsFold(f.members, "CONTOSO\\Ops") {
		t.Fatalf("revert should remove what the profile added, got %v", f.members)
	}
}

func containsFold(list []string, want string) bool {
	for _, got := range list {
		if strings.EqualFold(got, want) {
			return true
		}
	}
	return false
}
