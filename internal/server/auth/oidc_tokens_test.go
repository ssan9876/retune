package auth_test

import (
	"context"
	"errors"
	"testing"

	"retune/internal/server/auth"
	"retune/internal/server/auth/oidctest"
	"retune/internal/server/store"
)

// A token never has more access than the admin who made it has now: demoted
// in the identity provider, the admin's tokens are demoted with them.
func TestAPITokenFollowsItsMakersRole(t *testing.T) {
	f := newSSO(t)
	ctx := context.Background()
	person := oidctest.Person{Subject: "u-t1", Email: "dee@example.com", Groups: []string{"it-admins"}}
	admin, err := f.signIn(t, person, nil)
	if err != nil {
		t.Fatal(err)
	}
	plain, _, err := f.local.CreateAPIToken(ctx, auth.NewAPIToken{Name: "ci", Role: store.RoleAdmin, Creator: admin})
	if err != nil {
		t.Fatal(err)
	}
	if tok, err := f.local.AuthenticateAPIToken(ctx, plain); err != nil || tok.Role != store.RoleAdmin {
		t.Fatalf("before demotion: %v %v", tok.Role, err)
	}

	person.Groups = []string{"helpdesk"} // mapped to read-only in this fixture
	if _, err := f.signIn(t, person, nil); err != nil {
		t.Fatal(err)
	}
	tok, err := f.local.AuthenticateAPIToken(ctx, plain)
	if err != nil {
		t.Fatal(err)
	}
	if tok.Role != store.RoleReadOnly {
		t.Errorf("after demotion the token is %q, want %q", tok.Role, store.RoleReadOnly)
	}
}

// Someone taken out of every mapped group loses their API tokens as well as
// their sessions.
func TestSSOUnmappedAccountLosesItsAPITokens(t *testing.T) {
	f := newSSO(t)
	ctx := context.Background()
	person := oidctest.Person{Subject: "u-t2", Email: "eve@example.com", Groups: []string{"it-admins"}}
	admin, err := f.signIn(t, person, nil)
	if err != nil {
		t.Fatal(err)
	}
	plain, _, err := f.local.CreateAPIToken(ctx, auth.NewAPIToken{Name: "ci", Role: store.RoleAdmin, Creator: admin})
	if err != nil {
		t.Fatal(err)
	}

	person.Groups = nil
	if _, err := f.signIn(t, person, nil); ssoCode(err) != auth.SSOUnauthorized {
		t.Fatalf("want unauthorized, got %v", err)
	}
	if _, err := f.local.AuthenticateAPIToken(ctx, plain); !errors.Is(err, auth.ErrInvalidToken) {
		t.Errorf("the token should be revoked, got %v", err)
	}
	// Mapped again, the account works, but the token stays revoked.
	person.Groups = []string{"it-admins"}
	if _, err := f.signIn(t, person, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := f.local.AuthenticateAPIToken(ctx, plain); !errors.Is(err, auth.ErrInvalidToken) {
		t.Errorf("a revoked token should stay revoked, got %v", err)
	}
}
