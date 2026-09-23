# M17 OIDC SSO and Scoped Administrators Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** OpenID Connect sign-in with group-claim role mapping and just-in-time accounts, and per-administrator device-group scopes enforced on every device-addressing endpoint.

**Architecture:** `internal/server/auth/oidc.go` (flow + verification via go-oidc/oauth2), admin model gains `auth_source`/`oidc_subject`, new `admin_scopes` table, a `scope` helper in `internal/server/adminapi` applied to every device-addressing handler, a route-classification table checked by a test.

**Tech Stack:** Go 1.27, `github.com/coreos/go-oidc/v3`, `golang.org/x/oauth2`, pgx/v5, React 19 + vitest.

**Spec:** `docs/superpowers/specs/2026-09-15-m17-sso-scopes-design.md`

## Global Constraints

- Settings, flow, cookie, claims and audit names exactly as spec §2. PKCE S256; state+nonce cookie HMAC-signed with the server secret key, 10-minute expiry, `HttpOnly; Secure; SameSite=Lax`.
- Role re-derived at every OIDC sign-in; unmapped → refused, nothing created, `admin.login_refused` audited.
- Scoped admin: 404 for out-of-scope device ids; no mutation of item definitions, admins, tokens, alert channels, group definitions; assignments only to own groups.
- Every admin route is registered with a scope class (`scopeAware` or `unscopedOnly` or `public`); a test enumerates the mux and fails on any route without one.
- Only these two new dependencies. Tests use an in-process fake OIDC provider (`httptest` TLS server with discovery, JWKS, token endpoint, RSA and EC keys) — never a real IdP.
- Every single-row store query takes `tenantID` after `ctx`. Do not touch any Windows service. Do not run `go test ./...` inside a task.
- Go comments are prose explaining why. Commits conventional, ending with a blank line and `Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>`.

---

### Task 1: Config, migration, store

**Files:** `internal/config/server.go` (OIDC settings; enabled only when issuer+id+secret set), `internal/server/store/migrations/0014_sso_scopes.{up,down}.sql` (`admins.auth_source text NOT NULL DEFAULT 'local' CHECK (…)`, `admins.oidc_subject text`, unique `(tenant_id, oidc_subject)` where not null; `admin_scopes`), store methods (`GetAdminBySubject`, `CreateOIDCAdmin`, `UpdateAdminRole`, `DeleteSessionsForAdmin`, `SetAdminScopes`, `ListAdminScopes`) + tests.

- [ ] Commit `feat(store): OIDC-provisioned admins and admin scopes`.

### Task 2: OIDC flow

**Files:** `internal/server/auth/oidc.go` (+ fake provider test helper `oidctest` package), handlers `GET /oidc/start`, `GET /oidc/callback` in `internal/server/adminapi/oidc.go`, `GET /setup` gains `oidc: {enabled, display_name}` and `local_login: bool`, local login refused when disabled.

- [ ] Tests per spec §5 (success + JIT, re-derivation + session deletion on demotion, refusal, bad state/nonce/audience/expiry/issuer, local login disabled). Commit `feat(auth): OpenID Connect sign-in`.

### Task 3: Scope enforcement

**Files:** `internal/server/adminapi/scope.go` (resolve the caller's scope once per request into the request context; `deviceAllowed`, SQL predicate helpers), every device-addressing handler and list query (devices, device detail/software/compliance, BitLocker keys + reveal, admin passwords + reveal, commands list/queue/get, compliance device lists and exports, dashboard counts, CSV exports, assignments create/delete), route classification table + enumeration test, `PUT /admins/{id}/scopes`.

- [ ] Tests: for each scope-aware endpoint, a scoped admin sees only in-scope rows and gets 404 for an out-of-scope device; mutations of item definitions/admins/tokens/alert channels/groups are 403 for scoped admins; assignment to a foreign group 403; route enumeration test. Commit `feat(api): group-scoped administrators`.

### Task 4: Console, e2e, docs

**Files:** `web/src/pages/Login.tsx` (SSO button, local form hidden when disabled), `web/src/pages/Admins.tsx` (source column, scope editor), `web/src/components/Shell.tsx` (hide unusable nav for scoped admins, from `GET /session` scope info), tests; `test/e2e` (`TestSSOAndScopesEndToEnd` with the fake provider); `README.md` (SSO and scopes sections, settings table); roadmap (M17 row).

- [ ] Commit `feat(console): SSO sign-in and admin scopes`, `test(e2e): SSO and scopes`, `docs: single sign-on and scoped administrators`.
