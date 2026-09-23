package auth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"retune/internal/server/auth"
	"retune/internal/server/auth/oidctest"
	"retune/internal/server/store"
)

func makeGroup(t *testing.T, st *store.Store, name string) uuid.UUID {
	t.Helper()
	g := store.Group{ID: uuid.Must(uuid.NewV7()), Name: name, Kind: "static", CreatedAt: time.Now()}
	if err := st.Q().CreateGroup(context.Background(), g); err != nil {
		t.Fatal(err)
	}
	return g.ID
}

func scopeOf(t *testing.T, st *store.Store, id uuid.UUID) store.DeviceScope {
	t.Helper()
	s, err := st.Q().AdminScope(context.Background(), store.DefaultTenantID, id)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSSOScopesComeFromGroups(t *testing.T) {
	f := newSSO(t)
	emea := makeGroup(t, f.st, "EMEA laptops")
	us := makeGroup(t, f.st, "US laptops")
	f.sso.Config.ScopeGroups = map[string][]string{
		"helpdesk-emea": {"EMEA laptops"},
		"helpdesk-us":   {"US laptops"},
		"helpdesk-typo": {"Nonexistent group"},
	}
	f.sso.Config.FleetGroups = []string{"it-admins"}

	// One mapped group: scoped to it.
	ada := oidctest.Person{Subject: "u-1", Email: "ada@example.com", Groups: []string{"helpdesk", "helpdesk-emea"}}
	admin, err := f.signIn(t, ada, nil)
	if err != nil {
		t.Fatal(err)
	}
	if s := scopeOf(t, f.st, admin.ID); len(s) != 1 || s[0] != emea {
		t.Fatalf("scope = %v, want EMEA only", s)
	}
	if n := len(audits(t, f.st, "admin.scope_changed")); n != 1 {
		t.Errorf("scope_changed entries = %d", n)
	}

	// The same groups again: no change, nothing written.
	if _, err := f.signIn(t, ada, nil); err != nil {
		t.Fatal(err)
	}
	if n := len(audits(t, f.st, "admin.scope_changed")); n != 1 {
		t.Errorf("an unchanged scope was rewritten: %d entries", n)
	}

	// Added to another group at the provider: both, at the next sign-in.
	ada.Groups = append(ada.Groups, "helpdesk-us")
	if _, err := f.signIn(t, ada, nil); err != nil {
		t.Fatal(err)
	}
	if s := scopeOf(t, f.st, admin.ID); len(s) != 2 || !((s[0] == emea && s[1] == us) || (s[0] == us && s[1] == emea)) {
		t.Fatalf("scope = %v, want EMEA and US", s)
	}

	// In a fleet group: the whole fleet.
	bob := oidctest.Person{Subject: "u-2", Email: "bob@example.com", Groups: []string{"it-admins", "helpdesk-emea"}}
	b, err := f.signIn(t, bob, nil)
	if err != nil {
		t.Fatal(err)
	}
	if s := scopeOf(t, f.st, b.ID); s != nil {
		t.Fatalf("a fleet group's member is scoped to %v", s)
	}

	// A role but no device mapping: refused, never the whole fleet.
	cat := oidctest.Person{Subject: "u-3", Email: "cat@example.com", Groups: []string{"helpdesk"}}
	if _, err := f.signIn(t, cat, nil); ssoCode(err) != auth.SSOUnauthorized {
		t.Fatalf("no device mapping = %v", err)
	}

	// A mapping to a device group that doesn't exist narrows, and says so.
	dee := oidctest.Person{Subject: "u-4", Email: "dee@example.com", Groups: []string{"helpdesk", "helpdesk-typo"}}
	d, err := f.signIn(t, dee, nil)
	if err != nil {
		t.Fatal(err)
	}
	if s := scopeOf(t, f.st, d.ID); s == nil || len(s) != 0 {
		t.Fatalf("scope = %v, want limited to nothing", s)
	}
	var noted bool
	for _, e := range audits(t, f.st, "admin.scope_changed") {
		if e.TargetID == d.ID.String() && e.Details["unknown_groups"] != nil {
			noted = true
		}
	}
	if !noted {
		t.Error("the unknown group wasn't noted")
	}

	// Leaving every mapped group ends the account's sessions and refuses it.
	ada.Groups = []string{"helpdesk"}
	if _, err := f.signIn(t, ada, nil); ssoCode(err) != auth.SSOUnauthorized {
		t.Fatalf("after leaving the mapped groups = %v", err)
	}

	// With the provider in charge, the console can't change an SSO account's
	// scope.
	f.local.SSOScopesManaged = true
	if err := f.local.SetScope(context.Background(), admin.ID, nil, "ops"); !errors.Is(err, auth.ErrBadRequest) {
		t.Fatalf("SetScope on an SSO account = %v", err)
	}
}

func TestSSOScopesUntouchedWithoutAMapping(t *testing.T) {
	f := newSSO(t)
	g := makeGroup(t, f.st, "EMEA laptops")
	person := oidctest.Person{Subject: "u-1", Email: "ada@example.com", Groups: []string{"helpdesk"}}
	admin, err := f.signIn(t, person, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Scoped in the console, it stays that way across sign-ins.
	if err := f.local.SetScope(context.Background(), admin.ID, []uuid.UUID{g}, "ops"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.signIn(t, person, nil); err != nil {
		t.Fatal(err)
	}
	if s := scopeOf(t, f.st, admin.ID); len(s) != 1 || s[0] != g {
		t.Fatalf("scope = %v, want what the console set", s)
	}
}

// Admin outranks helpdesk, which outranks read-only.
func TestSSOHelpdeskGroup(t *testing.T) {
	f := newSSO(t)
	f.sso.Config.HelpdeskGroups = []string{"service-desk"}
	for subject, c := range map[string]struct {
		groups []string
		role   string
	}{
		"u-1": {[]string{"service-desk"}, store.RoleHelpdesk},
		"u-2": {[]string{"service-desk", "helpdesk"}, store.RoleHelpdesk},
		"u-3": {[]string{"service-desk", "it-admins"}, store.RoleAdmin},
	} {
		admin, err := f.signIn(t, oidctest.Person{Subject: subject, Email: subject + "@example.com", Groups: c.groups}, nil)
		if err != nil || admin.Role != c.role {
			t.Errorf("%v: role %q, %v; want %q", c.groups, admin.Role, err, c.role)
		}
	}
}
