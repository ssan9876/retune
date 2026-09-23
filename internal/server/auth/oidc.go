package auth

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"golang.org/x/oauth2"

	"retune/internal/config"
	"retune/internal/server/secrets"
	"retune/internal/server/store"
)

// LoginCookie carries a sign-in in progress from /oidc/start to the callback.
const LoginCookie = "retune_oidc"

// LoginTTL is how long somebody has at the identity provider before the
// sign-in they started is no longer accepted.
const LoginTTL = 10 * time.Minute

// sealContext binds a sealed login cookie to its purpose, so no other value
// sealed with the server's key can be passed off as one.
var sealContext = []byte("oidc-login")

// SSO refusal codes. They are what the console is told, in the redirect back
// to the sign-in page, and deliberately say no more than a person needs.
const (
	SSOUnavailable  = "unavailable"      // the provider could not be reached
	SSOBadState     = "state"            // no, expired, or mismatched sign-in in progress
	SSOExchange     = "exchange"         // the provider would not trade the code for tokens
	SSOBadToken     = "token"            // the ID token did not verify
	SSONoEmail      = "no_email"         // the token named nobody we can show
	SSOUnverified   = "email_unverified" // the provider says the email is not verified
	SSOUnauthorized = "unauthorized"     // in none of the mapped groups
	SSOEmailTaken   = "email_taken"      // a different account already uses the address
	SSODisabled     = "disabled"         // the account is disabled here
	SSOProvider     = "provider_error"   // the provider itself sent back an error
)

// SSOError is a sign-in refused, with the code the console turns into words.
type SSOError struct {
	Code string
	Err  error
}

func (e *SSOError) Error() string { return "sso " + e.Code + ": " + e.Err.Error() }
func (e *SSOError) Unwrap() error { return e.Err }

func refuse(code string, format string, args ...any) error {
	return &SSOError{Code: code, Err: fmt.Errorf(format, args...)}
}

// OIDC signs admins in through an OpenID Connect provider: the authorization
// code flow with PKCE, the ID token verified by go-oidc, and the account and
// its role worked out from the token at every sign-in.
type OIDC struct {
	Config      config.OIDCConfig
	RedirectURL string
	Key         *secrets.Key
	Store       *store.Store
	Now         func() time.Time
	// Client reaches the provider. Nil means the default client; tests pass
	// one that trusts their fake provider's certificate.
	Client *http.Client

	mu       sync.Mutex
	provider *oidc.Provider
}

// loginState is what the sealed cookie holds.
type loginState struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Expires  int64  `json:"e"`
}

func (o *OIDC) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

func (o *OIDC) ctx(ctx context.Context) context.Context {
	if o.Client != nil {
		return oidc.ClientContext(ctx, o.Client)
	}
	return ctx
}

// discover fetches the provider's configuration once and keeps it. A failure
// is not kept: a provider that was down when the first person tried must not
// stay broken until the server restarts.
func (o *OIDC) discover(ctx context.Context) (*oidc.Provider, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.provider != nil {
		return o.provider, nil
	}
	p, err := oidc.NewProvider(o.ctx(ctx), o.Config.Issuer)
	if err != nil {
		return nil, refuse(SSOUnavailable, "discover %s: %w", o.Config.Issuer, err)
	}
	o.provider = p
	return p, nil
}

func (o *OIDC) oauth(p *oidc.Provider) *oauth2.Config {
	return &oauth2.Config{
		ClientID: o.Config.ClientID, ClientSecret: o.Config.ClientSecret,
		Endpoint: p.Endpoint(), RedirectURL: o.RedirectURL,
		Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
	}
}

// Start begins a sign-in: where to send the browser, and the sealed cookie
// that proves on the way back that this browser is the one that started it.
func (o *OIDC) Start(ctx context.Context) (redirect, cookie string, err error) {
	p, err := o.discover(ctx)
	if err != nil {
		return "", "", err
	}
	state, err := randomToken()
	if err != nil {
		return "", "", err
	}
	nonce, err := randomToken()
	if err != nil {
		return "", "", err
	}
	ls := loginState{State: state, Nonce: nonce, Verifier: oauth2.GenerateVerifier(), Expires: o.now().Add(LoginTTL).Unix()}
	if cookie, err = o.seal(ls); err != nil {
		return "", "", err
	}
	redirect = o.oauth(p).AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(ls.Verifier))
	return redirect, cookie, nil
}

func (o *OIDC) seal(ls loginState) (string, error) {
	plain, err := json.Marshal(ls)
	if err != nil {
		return "", err
	}
	ciphertext, nonce, err := o.Key.Seal(plain, sealContext)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString(nonce) + "." + enc.EncodeToString(ciphertext), nil
}

func (o *OIDC) open(cookie string) (loginState, error) {
	var ls loginState
	nonceText, cipherText, ok := strings.Cut(cookie, ".")
	if !ok {
		return ls, errors.New("malformed login cookie")
	}
	enc := base64.RawURLEncoding
	nonce, err := enc.DecodeString(nonceText)
	if err != nil {
		return ls, err
	}
	ciphertext, err := enc.DecodeString(cipherText)
	if err != nil {
		return ls, err
	}
	plain, err := o.Key.Open(ciphertext, nonce, sealContext)
	if err != nil {
		return ls, err
	}
	return ls, json.Unmarshal(plain, &ls)
}

// Finish completes a sign-in from the callback's cookie, state and code, and
// returns the account to start a session for.
func (o *OIDC) Finish(ctx context.Context, cookie, state, code string) (store.Admin, error) {
	ls, err := o.open(cookie)
	if err != nil {
		return store.Admin{}, refuse(SSOBadState, "login cookie: %w", err)
	}
	if o.now().Unix() > ls.Expires {
		return store.Admin{}, refuse(SSOBadState, "the sign-in was started more than %s ago", LoginTTL)
	}
	if subtle.ConstantTimeCompare([]byte(state), []byte(ls.State)) != 1 {
		return store.Admin{}, refuse(SSOBadState, "state does not match the sign-in this browser started")
	}
	p, err := o.discover(ctx)
	if err != nil {
		return store.Admin{}, err
	}
	token, err := o.oauth(p).Exchange(o.ctx(ctx), code, oauth2.VerifierOption(ls.Verifier))
	if err != nil {
		return store.Admin{}, refuse(SSOExchange, "exchange the code: %w", err)
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok || raw == "" {
		return store.Admin{}, refuse(SSOBadToken, "the provider returned no ID token")
	}
	idToken, err := p.Verifier(&oidc.Config{ClientID: o.Config.ClientID, Now: o.now}).Verify(o.ctx(ctx), raw)
	if err != nil {
		return store.Admin{}, refuse(SSOBadToken, "verify the ID token: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(ls.Nonce)) != 1 {
		return store.Admin{}, refuse(SSOBadToken, "the ID token's nonce is not the one this sign-in sent")
	}
	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return store.Admin{}, refuse(SSOBadToken, "read the ID token's claims: %w", err)
	}
	// Accounts are keyed by subject, not email, so an unverified address
	// cannot take anyone's account; but it is still what the audit log
	// records as the actor. A provider that says outright the address is not
	// verified is refused. One that says nothing - Entra ID does not send the
	// claim - is taken at its word.
	if verified, present := claims["email_verified"].(bool); present && !verified {
		return store.Admin{}, refuse(SSOUnverified, "the provider says the email address is not verified")
	}
	email := stringClaim(claims, "email")
	if email == "" {
		email = stringClaim(claims, "preferred_username")
	}
	if email == "" {
		return store.Admin{}, refuse(SSONoEmail, "the ID token has neither email nor preferred_username")
	}
	groups := listClaim(claims, o.Config.GroupsClaim)
	return o.signIn(ctx, idToken.Issuer, idToken.Subject, email, o.role(groups), o.scope(groups))
}

// ssoScope is what a person's groups say about which devices they may
// manage, when the identity provider decides that.
type ssoScope struct {
	managed bool     // the provider decides scopes at all
	fleet   bool     // the whole fleet
	groups  []string // otherwise, these Retune device groups by name
}

// scope maps the groups a person is in to the device groups they manage.
// A fleet group wins; otherwise it is every device group their groups map
// to, and none at all is a refusal, never the whole fleet by default.
func (o *OIDC) scope(groups []string) ssoScope {
	if !o.Config.ManagesScopes() {
		return ssoScope{}
	}
	for _, g := range groups {
		if slices.Contains(o.Config.FleetGroups, g) {
			return ssoScope{managed: true, fleet: true}
		}
	}
	seen := map[string]bool{}
	var names []string
	for _, g := range groups {
		for _, name := range o.Config.ScopeGroups[g] {
			if !seen[strings.ToLower(name)] {
				seen[strings.ToLower(name)] = true
				names = append(names, name)
			}
		}
	}
	sort.Strings(names)
	return ssoScope{managed: true, groups: names}
}

// role maps the groups a person is in to a role: admin wins over read-only,
// and neither is no role at all.
func (o *OIDC) role(groups []string) string {
	for _, g := range groups {
		if slices.Contains(o.Config.AdminGroups, g) {
			return store.RoleAdmin
		}
	}
	for _, g := range groups {
		if slices.Contains(o.Config.HelpdeskGroups, g) {
			return store.RoleHelpdesk
		}
	}
	for _, g := range groups {
		if slices.Contains(o.Config.ReadOnlyGroups, g) {
			return store.RoleReadOnly
		}
	}
	return ""
}

// signIn finds or creates the account and records the sign-in. A refusal is
// still written to the audit log, so the transaction returns it as a value
// and it becomes an error only once the audit entry has committed.
func (o *OIDC) signIn(ctx context.Context, issuer, subject, email, role string, scope ssoScope) (store.Admin, error) {
	now := o.now()
	var admin store.Admin
	var refusal error
	refused := func(q *store.Queries, code, reason string, target string) error {
		refusal = refuse(code, "%s", reason)
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: email, Action: "admin.login_refused", TargetKind: "admin", TargetID: target,
			Details: map[string]any{"method": store.AuthOIDC, "reason": reason, "subject": subject},
		})
	}
	err := o.Store.InTx(ctx, func(q *store.Queries) error {
		existing, err := q.GetAdminByOIDC(ctx, store.DefaultTenantID, issuer, subject)
		found := err == nil
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		target := ""
		if found {
			target = existing.ID.String()
		}

		if role == "" {
			if found {
				// Their open sessions go too: someone removed from every
				// mapped group has been told no, and should not keep a
				// console open on the strength of an earlier yes.
				if err := q.DeleteSessionsForAdmin(ctx, existing.ID); err != nil {
					return err
				}
			}
			return refused(q, SSOUnauthorized, "not in any group mapped to a Retune role", target)
		}
		if scope.managed && !scope.fleet && len(scope.groups) == 0 {
			if found {
				if err := q.DeleteSessionsForAdmin(ctx, existing.ID); err != nil {
					return err
				}
			}
			return refused(q, SSOUnauthorized, "not in any group mapped to devices", target)
		}
		if found && existing.DisabledAt != nil {
			return refused(q, SSODisabled, "the account is disabled in Retune", target)
		}
		if other, err := q.GetAdminByEmail(ctx, store.DefaultTenantID, email); err == nil && (!found || other.ID != existing.ID) {
			return refused(q, SSOEmailTaken, "another account already uses "+email, target)
		} else if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}

		if found {
			admin = existing
			if existing.Email != email || existing.Role != role {
				if err := q.UpdateOIDCAdmin(ctx, store.DefaultTenantID, existing.ID, email, role); err != nil {
					return err
				}
				admin.Email, admin.Role = email, role
			}
			if existing.Role != role {
				if err := q.InsertAudit(ctx, store.AuditEntry{
					Actor: email, Action: "admin.role_changed", TargetKind: "admin", TargetID: target,
					Details: map[string]any{"from": existing.Role, "to": role, "method": store.AuthOIDC},
				}); err != nil {
					return err
				}
			}
		} else {
			id, err := uuid.NewV7()
			if err != nil {
				return err
			}
			admin = store.Admin{
				ID: id, Email: email, Role: role, CreatedAt: now,
				AuthSource: store.AuthOIDC, OIDCIssuer: issuer, OIDCSubject: subject,
			}
			if err := q.CreateAdmin(ctx, admin); err != nil {
				return err
			}
			target = id.String()
			if err := q.InsertAudit(ctx, store.AuditEntry{
				Actor: email, Action: "admin.provisioned", TargetKind: "admin", TargetID: target,
				Details: map[string]any{"role": role, "issuer": issuer},
			}); err != nil {
				return err
			}
		}
		if scope.managed {
			if err := applySSOScope(ctx, q, admin, scope, email); err != nil {
				return err
			}
		}
		if err := q.RecordAdminLogin(ctx, store.DefaultTenantID, admin.ID, now); err != nil {
			return err
		}
		admin.LastLoginAt = &now
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: email, Action: "admin.login", TargetKind: "admin", TargetID: target,
			Details: map[string]any{"method": store.AuthOIDC},
		})
	})
	if err != nil {
		return store.Admin{}, err
	}
	if refusal != nil {
		return store.Admin{}, refusal
	}
	return admin, nil
}

func stringClaim(claims map[string]any, name string) string {
	s, _ := claims[name].(string)
	return strings.TrimSpace(s)
}

// listClaim reads a claim that providers send as a list of strings, or, when
// there is only one, sometimes as a bare string.
func listClaim(claims map[string]any, name string) []string {
	switch v := claims[name].(type) {
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// applySSOScope sets an SSO account's device scope from its groups, and
// records a change. Device groups are named in the configuration; one that
// doesn't exist is skipped and noted, so a typo narrows access rather than
// widening it.
func applySSOScope(ctx context.Context, q *store.Queries, admin store.Admin, scope ssoScope, actor string) error {
	var want store.DeviceScope // nil: the whole fleet
	var names, missing []string
	if !scope.fleet {
		want = store.DeviceScope{}
		for _, name := range scope.groups {
			g, err := q.GetGroupByName(ctx, name)
			if errors.Is(err, store.ErrNotFound) {
				missing = append(missing, name)
				continue
			}
			if err != nil {
				return err
			}
			want = append(want, g.ID)
			names = append(names, g.Name)
		}
	}
	have, err := q.AdminScope(ctx, store.DefaultTenantID, admin.ID)
	if err != nil {
		return err
	}
	if sameScope(have, want) {
		return nil
	}
	if err := q.SetAdminScope(ctx, store.DefaultTenantID, admin.ID, want); err != nil {
		return err
	}
	details := map[string]any{"email": admin.Email, "scoped": want != nil, "method": store.AuthOIDC}
	if want != nil {
		details["groups"] = names
	}
	if len(missing) > 0 {
		details["unknown_groups"] = missing
	}
	return q.InsertAudit(ctx, store.AuditEntry{
		Actor: actor, Action: "admin.scope_changed", TargetKind: "admin", TargetID: admin.ID.String(),
		Details: details,
	})
}

func sameScope(a, b store.DeviceScope) bool {
	if (a == nil) != (b == nil) || len(a) != len(b) {
		return false
	}
	set := map[uuid.UUID]bool{}
	for _, id := range a {
		set[id] = true
	}
	for _, id := range b {
		if !set[id] {
			return false
		}
	}
	return true
}
