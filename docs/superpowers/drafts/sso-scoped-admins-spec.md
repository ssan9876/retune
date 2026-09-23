# M17 — Single sign-on (OIDC) and group-scoped administrators

Status: self-approved overnight under the user's standing directive; decisions ledgered for morning review. Builds on M1–M16.

## 1. What and why

Console accounts are local email + password (+ optional TOTP), with two roles: `admin` and `read_only`, both fleet-wide. Organisations want their identity provider (Entra ID, Okta, Google, Keycloak) to decide who gets in and with what role, and they want a helpdesk administrator who can manage one site's devices without seeing the rest. This milestone adds OpenID Connect sign-in with role mapping from a groups claim, and optional per-administrator scopes limiting them to named device groups.

## 2. OIDC sign-in

- Settings: `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_GROUPS_CLAIM` (default `groups`), `OIDC_ADMIN_GROUPS` and `OIDC_READONLY_GROUPS` (comma-separated claim values), `OIDC_DISPLAY_NAME` (button text, default "Sign in with SSO"), `OIDC_DISABLE_LOCAL_LOGIN` (default false). OIDC is enabled when issuer, client id and secret are all set; the redirect URL is `<PUBLIC_URL>/api/admin/v1/oidc/callback`.
- Flow: authorization code with PKCE (S256), `state` and `nonce` in a short-lived signed cookie (HMAC with the server secret key, 10-minute expiry). `GET /api/admin/v1/oidc/start` → provider; `GET /api/admin/v1/oidc/callback` → exchange, verify the ID token (issuer, audience, expiry, nonce; RS256/ES256 via the provider's JWKS), map groups → role, then the existing `CreateSession` and the existing cookie/CSRF handling.
- Libraries: `github.com/coreos/go-oidc/v3` and `golang.org/x/oauth2`. ID-token verification is security-critical; a vetted implementation beats a hand-written JWT verifier.
- Accounts are provisioned just in time: the first sign-in creates an admin with `auth_source = 'oidc'`, the provider's `sub` stored as `oidc_subject` (unique per tenant), email from the `email` claim. The role is re-derived from the groups claim at **every** sign-in: removing someone from the IdP group demotes or locks them at their next login, and existing sessions of an admin whose mapped role disappears are deleted at that point. A user in neither group is refused ("your account is not authorised for Retune") and nothing is created.
- OIDC admins have no password and no TOTP (the IdP owns MFA). Local accounts keep working as break-glass unless `OIDC_DISABLE_LOCAL_LOGIN=true`; `bootstrap-admin` always works from the CLI.
- Audit: `admin.login` gains `method: local|oidc`; `admin.provisioned` on JIT creation; `admin.login_refused` with the reason for an unmapped user.

## 3. Group-scoped administrators

- Table `admin_scopes(admin_id, group_id, tenant_id, PRIMARY KEY (admin_id, group_id))`. An admin with **no** rows is unscoped (today's behaviour). An admin with rows is scoped to the union of those device groups (static and dynamic membership, as the assignment engine already computes).
- A scoped admin:
  - sees only devices in their groups — devices list, device detail, software, BitLocker keys and reveal, admin passwords and reveal, commands (list and queue), compliance results, CSV export, dashboard counts;
  - may create and delete assignments only whose target group is one of theirs;
  - sees item definitions (scripts, profiles, apps, agent versions, compliance policies) read-only and cannot create, edit or delete them;
  - cannot manage admins, tokens, alert channels, or groups' definitions;
  - gets 404 (not 403) for a device outside their scope, so device ids cannot be probed.
- Enforcement is one helper used everywhere a device is addressed — `scope.Devices(ctx, admin)` returning either "all" or a device-id predicate applied in SQL (`device_id = ANY(…)` or a join on group membership) — plus a route-level flag for the unscoped-only endpoints. A test enumerates every admin route and asserts each is either scope-aware or unscoped-only, so a future route cannot forget.
- Only unscoped `admin`-role accounts can set scopes (`PUT /admins/{id}/scopes`), audited `admin.scopes_changed`.

## 4. Console

Login page shows the SSO button when OIDC is enabled (from `GET /setup`) and hides the password form when local login is disabled. The Admins page shows each account's source (local/OIDC) and a scope editor (group multi-select). A scoped admin's navigation omits the pages they cannot use.

## 5. Testing

An in-process fake OIDC provider (discovery, JWKS, token endpoint, signing keys) drives: successful sign-in and JIT provisioning; role re-derivation and demotion; refusal of unmapped users; bad state, bad nonce, wrong audience, expired token, wrong issuer; local login disabled. Scope tests: every scoped endpoint returns only in-scope rows and 404s out-of-scope device ids; the route-enumeration test; scoped admin cannot mutate item definitions or admins. Console tests for the login variants and the scope editor.
