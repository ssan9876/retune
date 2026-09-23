package auth_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"retune/internal/config"
	"retune/internal/server/auth"
	"retune/internal/server/auth/oidctest"
	"retune/internal/server/secrets"
	"retune/internal/server/store"
	"retune/internal/server/store/storetest"
)

// ssoFixture is a Retune server's SSO side wired to a fake provider.
type ssoFixture struct {
	idp   *oidctest.Provider
	sso   *auth.OIDC
	local *auth.Service
	st    *store.Store
	clock *time.Time
}

func newSSO(t *testing.T) *ssoFixture {
	t.Helper()
	idp := oidctest.New(t, "retune-console")
	raw := make([]byte, secrets.KeySize)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	key, err := secrets.FromHex(hex.EncodeToString(raw))
	if err != nil {
		t.Fatal(err)
	}
	st := storetest.New(t)
	clock := time.Now()
	now := func() time.Time { return clock }
	return &ssoFixture{
		idp: idp, st: st, clock: &clock,
		sso: &auth.OIDC{
			Config: config.OIDCConfig{
				Issuer: idp.Issuer(), ClientID: "retune-console", ClientSecret: "shh", GroupsClaim: "groups",
				AdminGroups: []string{"it-admins"}, ReadOnlyGroups: []string{"helpdesk"},
			},
			RedirectURL: "https://retune.example.com/api/admin/v1/oidc/callback",
			Key:         key, Store: st, Now: now, Client: idp.Client(),
		},
		local: &auth.Service{Store: st, Now: now, SessionTTL: time.Hour},
	}
}

// signIn runs the whole flow for person, with optional claim overrides, and
// returns what Finish returned.
func (f *ssoFixture) signIn(t *testing.T, person oidctest.Person, extra map[string]any) (store.Admin, error) {
	t.Helper()
	ctx := context.Background()
	redirect, cookie, err := f.sso.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	state, code := f.idp.Authorize(t, redirect, person, extra)
	return f.sso.Finish(ctx, cookie, state, code)
}

func ssoCode(err error) string {
	var sso *auth.SSOError
	if errors.As(err, &sso) {
		return sso.Code
	}
	return ""
}

func audits(t *testing.T, st *store.Store, action string) []store.AuditEntry {
	t.Helper()
	all, err := st.Q().ListAudit(context.Background(), 200)
	if err != nil {
		t.Fatal(err)
	}
	var out []store.AuditEntry
	for _, e := range all {
		if e.Action == action {
			out = append(out, e)
		}
	}
	return out
}

func TestSSOProvisionsOnFirstSignInAndReusesAfter(t *testing.T) {
	f := newSSO(t)
	person := oidctest.Person{Subject: "u-1", Email: "ada@example.com", Groups: []string{"helpdesk"}}

	first, err := f.signIn(t, person, nil)
	if err != nil {
		t.Fatal(err)
	}
	if first.AuthSource != store.AuthOIDC || first.Role != store.RoleReadOnly || first.Email != "ada@example.com" ||
		first.PasswordHash != "" || first.OIDCIssuer != f.idp.Issuer() || first.OIDCSubject != "u-1" {
		t.Fatalf("provisioned = %+v", first)
	}
	if n := len(audits(t, f.st, "admin.provisioned")); n != 1 {
		t.Errorf("want one admin.provisioned, got %d", n)
	}

	// Same person, promoted at the provider and renamed: same account, new
	// role and email, and the change is on the record.
	person.Groups, person.Email = []string{"helpdesk", "it-admins"}, "ada.l@example.com"
	second, err := f.signIn(t, person, nil)
	if err != nil {
		t.Fatal(err)
	}
	if second.ID != first.ID || second.Role != store.RoleAdmin || second.Email != "ada.l@example.com" {
		t.Fatalf("second sign-in = %+v", second)
	}
	changed := audits(t, f.st, "admin.role_changed")
	if len(changed) != 1 || changed[0].Details["from"] != store.RoleReadOnly || changed[0].Details["to"] != store.RoleAdmin {
		t.Errorf("role change audit = %+v", changed)
	}
	logins := audits(t, f.st, "admin.login")
	if len(logins) != 2 || logins[0].Details["method"] != store.AuthOIDC {
		t.Errorf("login audits = %+v", logins)
	}
}

func TestSSORefusesSomeoneInNoMappedGroup(t *testing.T) {
	f := newSSO(t)
	_, err := f.signIn(t, oidctest.Person{Subject: "u-2", Email: "eve@example.com", Groups: []string{"sales"}}, nil)
	if ssoCode(err) != auth.SSOUnauthorized {
		t.Fatalf("want unauthorized, got %v", err)
	}
	if n, _ := f.st.Q().CountAdmins(context.Background()); n != 0 {
		t.Errorf("nothing should be created for a refused person, have %d admins", n)
	}
	if refused := audits(t, f.st, "admin.login_refused"); len(refused) != 1 || refused[0].Details["subject"] != "u-2" {
		t.Errorf("the refusal should be audited: %+v", refused)
	}
}

// Someone taken out of every mapped group is refused at their next sign-in,
// and loses the sessions they already had.
func TestSSOUnmappedAccountLosesItsSessions(t *testing.T) {
	f := newSSO(t)
	ctx := context.Background()
	person := oidctest.Person{Subject: "u-3", Email: "bob@example.com", Groups: []string{"it-admins"}}
	admin, err := f.signIn(t, person, nil)
	if err != nil {
		t.Fatal(err)
	}
	session, err := f.local.CreateSession(ctx, admin.ID, "test", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	person.Groups = nil
	if _, err := f.signIn(t, person, nil); ssoCode(err) != auth.SSOUnauthorized {
		t.Fatalf("want unauthorized, got %v", err)
	}
	if _, _, err := f.local.ValidateSession(ctx, session.Token); !errors.Is(err, auth.ErrInvalidSession) {
		t.Errorf("the open session should be gone, got %v", err)
	}
}

// A provider's user is never merged into a local account by email: not every
// provider verifies addresses, and the merge would be a takeover.
func TestSSORefusesAnEmailALocalAccountUses(t *testing.T) {
	f := newSSO(t)
	if _, err := f.local.CreateAdmin(context.Background(), auth.CreateAdminOptions{
		Email: "root@example.com", Password: "a long local password", Role: store.RoleAdmin, Actor: "cli",
	}); err != nil {
		t.Fatal(err)
	}
	_, err := f.signIn(t, oidctest.Person{Subject: "u-4", Email: "ROOT@example.com", Groups: []string{"it-admins"}}, nil)
	if ssoCode(err) != auth.SSOEmailTaken {
		t.Fatalf("want email_taken, got %v", err)
	}
}

func TestSSORefusesADisabledAccount(t *testing.T) {
	f := newSSO(t)
	ctx := context.Background()
	person := oidctest.Person{Subject: "u-5", Email: "cy@example.com", Groups: []string{"it-admins"}}
	admin, err := f.signIn(t, person, nil)
	if err != nil {
		t.Fatal(err)
	}
	// A second admin, so disabling the first is not disabling the last.
	if _, err := f.local.CreateAdmin(ctx, auth.CreateAdminOptions{
		Email: "other@example.com", Password: "a long local password", Role: store.RoleAdmin, Actor: "cli",
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.local.SetDisabled(ctx, admin.ID, true, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.signIn(t, person, nil); ssoCode(err) != auth.SSODisabled {
		t.Fatalf("want disabled, got %v", err)
	}
}

func TestSSORefusesBadProtocol(t *testing.T) {
	f := newSSO(t)
	ctx := context.Background()
	person := oidctest.Person{Subject: "u-6", Email: "dan@example.com", Groups: []string{"it-admins"}}

	cases := map[string]struct {
		run  func() error
		code string
	}{
		"state mismatch": {func() error {
			redirect, cookie, _ := f.sso.Start(ctx)
			_, code := f.idp.Authorize(t, redirect, person, nil)
			_, err := f.sso.Finish(ctx, cookie, "not-the-state", code)
			return err
		}, auth.SSOBadState},
		"no cookie": {func() error {
			redirect, _, _ := f.sso.Start(ctx)
			state, code := f.idp.Authorize(t, redirect, person, nil)
			_, err := f.sso.Finish(ctx, "", state, code)
			return err
		}, auth.SSOBadState},
		"another browser's cookie": {func() error {
			_, otherCookie, _ := f.sso.Start(ctx)
			redirect, _, _ := f.sso.Start(ctx)
			state, code := f.idp.Authorize(t, redirect, person, nil)
			_, err := f.sso.Finish(ctx, otherCookie, state, code)
			return err
		}, auth.SSOBadState},
		"started too long ago": {func() error {
			redirect, cookie, _ := f.sso.Start(ctx)
			state, code := f.idp.Authorize(t, redirect, person, nil)
			*f.clock = f.clock.Add(auth.LoginTTL + time.Minute)
			defer func() { *f.clock = f.clock.Add(-(auth.LoginTTL + time.Minute)) }()
			_, err := f.sso.Finish(ctx, cookie, state, code)
			return err
		}, auth.SSOBadState},
		"wrong nonce": {func() error {
			_, err := f.signIn(t, person, map[string]any{"nonce": "replayed"})
			return err
		}, auth.SSOBadToken},
		"wrong audience": {func() error {
			_, err := f.signIn(t, person, map[string]any{"aud": "some-other-app"})
			return err
		}, auth.SSOBadToken},
		"wrong issuer": {func() error {
			_, err := f.signIn(t, person, map[string]any{"iss": "https://evil.example.com"})
			return err
		}, auth.SSOBadToken},
		"expired": {func() error {
			_, err := f.signIn(t, person, map[string]any{"exp": time.Now().Add(-time.Hour).Unix()})
			return err
		}, auth.SSOBadToken},
		"signed by another key": {func() error {
			redirect, cookie, _ := f.sso.Start(ctx)
			state, code := f.idp.ForgeCode(t, redirect, person)
			_, err := f.sso.Finish(ctx, cookie, state, code)
			return err
		}, auth.SSOBadToken},
		"code used twice": {func() error {
			redirect, cookie, _ := f.sso.Start(ctx)
			state, code := f.idp.Authorize(t, redirect, person, nil)
			if _, err := f.sso.Finish(ctx, cookie, state, code); err != nil {
				return err
			}
			_, err := f.sso.Finish(ctx, cookie, state, code)
			return err
		}, auth.SSOExchange},
		"unverified email": {func() error {
			_, err := f.signIn(t, person, map[string]any{"email_verified": false})
			return err
		}, auth.SSOUnverified},
		"no email": {func() error {
			_, err := f.signIn(t, oidctest.Person{Subject: "u-7", Groups: []string{"it-admins"}}, nil)
			return err
		}, auth.SSONoEmail},
	}
	for name, tc := range cases {
		if got := ssoCode(tc.run()); got != tc.code {
			t.Errorf("%s: code %q, want %q", name, got, tc.code)
		}
	}
	// None of these is audited: anyone can produce them, and a flood would
	// bury the entries that matter.
	if refused := audits(t, f.st, "admin.login_refused"); len(refused) != 0 {
		t.Errorf("protocol failures should not be audited: %+v", refused)
	}
}

// The groups claim may arrive as a single string when there is only one.
func TestSSOAcceptsAGroupsClaimThatIsAString(t *testing.T) {
	f := newSSO(t)
	admin, err := f.signIn(t, oidctest.Person{Subject: "u-8", Email: "fay@example.com"}, map[string]any{"groups": "it-admins"})
	if err != nil || admin.Role != store.RoleAdmin {
		t.Fatalf("got %+v, %v", admin, err)
	}
}

func TestSSOAccountsHaveNoPasswordPath(t *testing.T) {
	f := newSSO(t)
	ctx := context.Background()
	admin, err := f.signIn(t, oidctest.Person{Subject: "u-9", Email: "gus@example.com", Groups: []string{"it-admins"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.local.Authenticate(ctx, "gus@example.com", "", ""); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("the password form must treat an SSO account as unknown, got %v", err)
	}
	for name, err := range map[string]error{
		"password":     f.local.SetPassword(ctx, admin.ID, "a brand new password", "test"),
		"disable totp": f.local.DisableTOTP(ctx, admin.ID, "test"),
		"enable totp": func() error {
			_, _, err := f.local.EnableTOTP(ctx, admin.ID, "test")
			return err
		}(),
	} {
		if !errors.Is(err, auth.ErrBadRequest) || !strings.Contains(err.Error(), "SSO") {
			t.Errorf("%s: want a refusal naming SSO, got %v", name, err)
		}
	}
}

func TestLocalLoginCanBeTurnedOff(t *testing.T) {
	f := newSSO(t)
	ctx := context.Background()
	if _, err := f.local.CreateAdmin(ctx, auth.CreateAdminOptions{
		Email: "root@example.com", Password: "a long local password", Role: store.RoleAdmin, Actor: "cli",
	}); err != nil {
		t.Fatal(err)
	}
	f.local.LocalLoginDisabled = true
	if _, err := f.local.Authenticate(ctx, "root@example.com", "a long local password", ""); !errors.Is(err, auth.ErrLocalLoginDisabled) {
		t.Fatalf("want ErrLocalLoginDisabled, got %v", err)
	}
}
