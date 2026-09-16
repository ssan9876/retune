# M13 — Multi-tenancy: making `tenant_id` mean something

Status: **draft for review** — not approved, nothing implemented. Builds on
merged M1–M12. Extends the core-platform spec
(`2026-09-12-core-platform-design.md`) and the M11 hardening spec
(`2026-09-14-m11-hardening-design.md`), which scoped the single-row queries
this milestone finishes the job of.

## 1. Why

Every table in the schema has carried a `tenant_id` since migration 0001, with
a foreign key to `tenants` and one seeded row:

```sql
INSERT INTO tenants (id, name) VALUES ('00000000-0000-0000-0000-000000000001', 'default');
```

The columns are real, the foreign keys are real, and the unique indexes are
already tenant-scoped (`admins (tenant_id, lower(email))`, the device serial
and SMBIOS indexes). What is missing is anything above the store layer that
knows which tenant is asking: **234 call sites pass `store.DefaultTenantID`**,
a package-level variable. The isolation is spelled out in the schema and then
thrown away one line above it.

This matters in two directions:

- **For an MSP or a group of business units**, the product cannot be sold as
  it stands. Two customers on one server would see each other's devices.
- **For the codebase**, `DefaultTenantID` is a permanent invitation to write a
  query that ignores tenancy. M11 fixed the single-row queries by taking
  `tenantID uuid.UUID` as a parameter — and every caller passes the constant,
  so the parameter documents an intention nothing enforces.

The goal of this milestone is that **a query that does not name a tenant does
not compile**.

## 2. Scope

In scope:

- Tenant resolution for admin requests, agent requests and CLI commands.
- Removing `store.DefaultTenantID` entirely.
- Tenant lifecycle: creating, listing, renaming and disabling tenants.
- Per-tenant artifact storage on disk.
- The console showing which tenant the signed-in admin is working in.

Out of scope, deliberately:

- **A per-tenant CA.** One server CA keeps issuing device certificates; a
  device's tenant comes from its device row, not from its certificate chain.
  Per-tenant CAs are a bigger change to enrollment, renewal and pinning than
  the isolation gains here justify.
- **A cross-tenant "platform administrator" role.** See §4.3 — this is the
  decision most worth arguing about, and the recommendation is to do without
  one for now.
- **Per-tenant configuration** (session TTL, check-in interval, TLS). Server
  config stays server-wide.
- **Billing, quotas, tenant self-service signup.** Nothing in the product
  implies them yet.

## 3. How a request finds its tenant

Three entry points, three answers, none of which is a header the caller
controls:

| Caller | Tenant comes from |
|---|---|
| Admin console / admin API | the signed-in admin's own `admins.tenant_id`, carried on the session |
| Agent | the device row the client certificate resolves to (`devices.tenant_id`) |
| Enrolling agent | the enrollment token's `enrollment_tokens.tenant_id` |
| Server CLI | an explicit `--tenant <name>` flag, no default |

The enrollment path already works this way: a token belongs to a tenant, and
the device it enrols inherits it. Nothing about agent-side code changes in
this milestone — the agent never learns it has a tenant, which is as it should
be.

**No tenant is ever taken from a request header, a subdomain or a query
parameter.** An admin cannot ask for another tenant's data by asking
differently; they would have to be a different admin.

## 4. Mechanics

### 4.1 A tenant-scoped query handle

The shape that makes the compiler do the work:

```go
// Today
q := st.Q()
devices, err := q.ListDevices(ctx, page)          // tenant: whatever the query hardcodes

// Proposed
q := st.For(tenantID)                             // *Queries, bound to one tenant
devices, err := q.ListDevices(ctx, page)          // tenant: the one the handle carries
```

`Queries` gains an unexported `tenant uuid.UUID` field, every query uses it,
and `st.Q()` is removed along with `DefaultTenantID`. There is then no way to
reach a query without having named a tenant first, and the 234 call sites
become a compile error rather than a code-review obligation. The single-row
queries M11 gave a `tenantID` parameter drop it again — the handle carries it,
and two sources of the same fact is one too many.

Services (`compliance.Service`, `groups.Service`, …) keep taking a `*Store`
and take the tenant per call, because a service outlives any one request and
serves every tenant. The sweeper is the interesting case: it iterates tenants
and runs each job once per tenant, under the same advisory lock per job (§4.4).

### 4.2 Why not Postgres row-level security

RLS with `SET LOCAL app.tenant_id` per transaction is the other credible
design, and it is stronger: it survives a query someone writes wrongly. It is
not recommended here because pgx's pooling makes the `SET LOCAL` discipline
easy to get subtly wrong, every test fixture would have to adopt it, and the
failure mode of a missed `SET LOCAL` is *silently seeing nothing*, which is
harder to notice in a test than a compile error. §4.1 fails loudly at build
time instead. RLS remains a reasonable later addition as defence in depth, on
top of §4.1 rather than instead of it.

### 4.3 The decision worth arguing about: cross-tenant admins

Three options:

1. **One admin, one tenant** (recommended). An admin row already has a
   `tenant_id`, and `admins (tenant_id, lower(email))` is already the unique
   index — the same email can exist in two tenants as two accounts with two
   passwords and two TOTP secrets. Nothing in the session, the API or the
   console needs a tenant selector. An MSP operator managing five customers
   signs in five times.
2. **A platform role that can act in any tenant**, with a tenant switcher in
   the console. Convenient for exactly the MSP case, and it puts a
   cross-tenant blast radius back into a single stolen session — the thing
   this milestone exists to remove.
3. **Admin-to-tenant as a join table**, one account with an explicit list.
   The honest general answer, and the most work: session, audit, every
   authorization check and the console all grow a "which tenant am I in right
   now" dimension.

Recommendation: **(1) for M13**, because it needs no new authorization
concepts and cannot leak across tenants by construction. (3) is the upgrade
path if the MSP case turns out to be the product's actual shape; (2) is the
one to avoid, since it is (3) with the safety removed.

### 4.4 Sweepers

Jobs today run once per tick over "every active device". With tenants they run
once per tick **per tenant**, keeping one advisory lock per job (not per job
per tenant) so a replica still runs the whole pass or none of it. A tenant
whose pass fails is logged and skipped; it must not stop the next tenant's,
the same way one device's failure does not stop the next device's today.

### 4.5 Artifacts on disk

`artifacts.Store` keys agent builds by version string:

```go
func (s Store) Put(version string, r io.Reader, limit int64) (sha256Hex string, size int64, err error)
```

Two tenants uploading `0.3.0` would collide on one path today, and
`agent_versions` already has a `tenant_id`. The path becomes
`<data-dir>/agents/<tenant-id>/<version>`, with a migration step that moves
existing files under the default tenant's id. This is the one piece of state
outside Postgres that tenancy touches.

### 4.6 Tenant lifecycle

Creating a tenant is an operator action, not an admin-API action — a tenant
that could create tenants is a platform role by another name (§4.3). So it
lives beside the existing server CLI commands:

```
retune-server tenant create --name "Contoso"
retune-server tenant list
retune-server tenant rename --tenant contoso --name "Contoso Ltd"
retune-server tenant disable --tenant contoso
retune-server bootstrap-admin --tenant contoso --email ops@contoso.example
```

`bootstrap-admin` gains a required `--tenant`. Disabling a tenant refuses new
sessions and check-ins but deletes nothing; there is no tenant delete in this
milestone, because a wrong one is unrecoverable and nothing yet needs it.

### 4.7 Migration and compatibility

No data migration is needed: every existing row is already in the default
tenant, and it stays. An existing single-tenant deployment sees one behaviour
change — CLI commands now need `--tenant`, for which the default tenant's name
(`default`) is what they pass.

## 5. Console

- The shell shows the current tenant's name beside the signed-in admin.
- No tenant switcher (§4.3 option 1).
- Otherwise unchanged: every page already asks for "the" devices, groups and
  policies, and now gets the signed-in admin's tenant's.

## 6. Testing

- A store-level test per table family asserting that a handle for tenant A
  cannot read, update or delete tenant B's row — the test that would have
  caught this whole class of bug, and which cannot be written today because
  there is only one tenant.
- An app-level test signing in as an admin of each of two tenants and walking
  the full admin API, asserting each sees only its own.
- An end-to-end test enrolling one device per tenant with that tenant's token,
  and asserting each device's check-in returns only its own tenant's items.
- The existing suites keep passing with a default tenant, so the milestone is
  a refactor everywhere except where it is a feature.

## 7. Size and risk

Large but shallow: 234 call sites, mechanical, and the compiler names every
one. The risky parts are few and named above — the sweeper's per-tenant loop
(§4.4), the artifact path move (§4.5), and the `admins`/session plumbing
(§4.3). It is a good fit for the subagent-driven plan the other milestones
used, split roughly as: the store handle; each service family; the admin API
and session; the agent API and enrollment; the sweeper; artifacts; the CLI;
the console; the tests in §6.

## 8. Open questions for review

1. §4.3 — is the MSP case (one person, many tenants) real for this product? If
   yes, option (3) belongs in M13 rather than after it, because retrofitting a
   join table across sessions and audit is worse than starting with one.
2. Is a per-tenant CA wanted eventually? It is out of scope here, but if the
   answer is "yes, in a year", the enrollment work in this milestone should at
   least not make it harder.
3. Should a disabled tenant's devices keep checking in read-only, or be
   refused outright? §4.6 assumes refused.
