# M12 Compliance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Server-evaluated compliance policies assigned to groups, an overview dashboard, and CSV export.

**Architecture:** New `internal/server/compliance` package (pure rule engine + service), migration 0011, admin endpoints, a sweeper job, and a hook in inventory ingest. Results mirrored into `device_item_status` so existing rollups work. No agent change.

**Tech Stack:** Go 1.27, pgx/v5, golang-migrate, React 19 + vitest.

**Spec:** `docs/superpowers/specs/2026-09-15-m12-compliance-design.md`

## Global Constraints

- Item kind string: `compliance`. States: `compliant`, `non_compliant`, `unknown`; derived overall adds `not_evaluated`.
- Mirror mapping into `device_item_status`: compliant→`succeeded`, non_compliant→`failed`, unknown→`pending`; version 1; detail = failures' details joined by `"; "`.
- Rules: JSON array, 1–50 entries, strict parsing, the twelve types and bounds exactly as in spec §3.
- Every single-row store query takes `tenantID uuid.UUID` after `ctx` and filters on `tenant_id` (M11 convention); callers pass `store.DefaultTenantID`.
- CSV cells beginning with `=`, `+`, `-`, `@`, `\t`, `\r` are prefixed with `'`.
- No new Go dependencies. No agent code changes.
- Do not install, start, stop or touch any Windows service; do not run `go test ./...` inside a task; `-race` is CI-only (no CGO here).
- Go comments are prose explaining why, in the surrounding voice. Commit messages conventional, ending with a blank line and `Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>`.

---

### Task 1: Migration and store

**Files:** Create `internal/server/store/migrations/0011_compliance.{up,down}.sql`, `internal/server/store/compliance.go`, `internal/server/store/compliance_test.go`.

**Produces:**
- `type CompliancePolicy struct{ ID uuid.UUID; Name, Description string; Rules []byte /* raw JSON */; CreatedAt, UpdatedAt time.Time; CreatedBy string }`
- `CreateCompliancePolicy(ctx, p) error` (ErrDuplicate on name clash, like `CreateAgentVersion`), `GetCompliancePolicy(ctx, tenantID, id)`, `ListCompliancePolicies(ctx, page) ([]CompliancePolicy, int, error)`, `UpdateCompliancePolicy(ctx, tenantID, p) error` (name, description, rules, updated_at; ErrDuplicate on clash), `DeleteCompliancePolicy(ctx, tenantID, id) error`.
- `type DeviceCompliance struct{ DeviceID, PolicyID uuid.UUID; Hostname string /* list queries only */; State string; Failures []byte /* JSON array */; EvaluatedAt time.Time }`
- `UpsertDeviceCompliance(ctx, dc) error`, `DeleteDeviceComplianceExcept(ctx, deviceID uuid.UUID, keep []uuid.UUID) error` (removes rows for policies not in `keep`), `DeleteComplianceForPolicy(ctx, policyID) error`, `ListDeviceCompliance(ctx, deviceID) ([]DeviceCompliance, error)`, `ListPolicyCompliance(ctx, policyID, state string, page) ([]DeviceCompliance, int, error)` (joins devices for hostname, ordered by lower(hostname)).
- `ComplianceOverall(ctx, deviceIDs []uuid.UUID) (map[uuid.UUID]string, error)` — derived overall state per device (§2), `not_evaluated` for devices with no rows.
- `ComplianceCounts(ctx) (map[string]int, error)` — overall-state counts across active devices (including `not_evaluated`).
- Also `DeleteItemStatusForItem(ctx, kind string, itemID uuid.UUID) error` and `DeleteItemStatusExcept(ctx, deviceID uuid.UUID, kind string, keep []uuid.UUID) error` in `itemstatus.go` if equivalents do not already exist (check first; reuse if they do).

- [ ] Write store tests first (round-trip, duplicate name, tenant scoping on the single-row methods, `DeleteDeviceComplianceExcept`, overall derivation for all four outcomes, counts), watch them fail, implement, pass. Commit `feat(store): compliance policies and per-device results`.

### Task 2: Rule engine

**Files:** Create `internal/server/compliance/rules.go`, `rules_test.go`.

**Produces:**
- `type Rule struct` (internal representation per type), `func ParseRules(raw []byte) ([]Rule, error)` returning errors wrapping `ErrBadRules`, and `func (r Rule) MarshalJSON` / canonical `MarshalRules([]Rule) ([]byte, error)`.
- `type Facts struct{ Device store.Device; Inventory *protocol.Inventory; InventoryReceivedAt *time.Time; ProfileStatus map[uuid.UUID]string }`
- `type Failure struct{ Rule, State, Detail string }` (JSON `rule`, `state`, `detail`), `type Result struct{ State string; Failures []Failure }`
- `func Evaluate(rules []Rule, f Facts, now time.Time) Result`
- `func CompareDotted(a, b string) (int, bool)` — segment-wise numeric; false when either is not dotted-numeric.

- [ ] Table tests for every type: compliant, non-compliant, unknown, boundary (exactly at the limit), plus parse rejections (unknown type, unknown field, out-of-range bound, 0 rules, 51 rules, bad uuid). Details must be the plain sentences of spec §3. Commit `feat(compliance): rule engine`.

### Task 3: Service

**Files:** Create `internal/server/compliance/service.go`, `service_test.go`.

**Produces:** `type Service struct{ Store *store.Store; Now func() time.Time; Log *slog.Logger }` with `Create(ctx, NewPolicy{Name, Description string; Rules json.RawMessage; Actor string})`, `Get`, `List`, `Update(ctx, id, NewPolicy)`, `Delete(ctx, id, actor)` (assignments via `DeleteAssignmentsForItem`, results, mirrored statuses, audit — one transaction), `EvaluateDevice(ctx, deviceID) error`, `EvaluatePolicy(ctx, policyID) (int, error)` (every device the policy currently applies to — use the assignment engine's member resolution the way other kinds' status pages do; if no helper exists, evaluate every active device and let `EvaluateDevice` decide), `EvaluateActive(ctx, q *store.Queries, now time.Time) (int64, error)` (sweeper signature). Errors `ErrNotFound`, `ErrBadRequest`, `ErrNameTaken`.

`EvaluateDevice`: load device; its effective items of kind `compliance`; for each, load the policy, parse rules (a policy whose stored rules no longer parse is logged and treated as all-unknown with detail "this policy's rules could not be read"); build Facts once (inventory JSON parsed into `protocol.Inventory`; profile statuses of kind `profile` for the device); evaluate; upsert result and mirrored item status; then delete rows for policies no longer applicable.

- [ ] Tests with `storetest.New(t)`: evaluation writes both tables with the mapping; unassigning removes both; overall derivation through `ComplianceOverall`; Delete clears everything and audits; name clash → `ErrNameTaken`; bad rules → `ErrBadRequest`. Commit `feat(compliance): policy service and evaluation`.

### Task 4: Wiring

**Files:** Modify `internal/server/adminapi/itemkinds.go` (kind `compliance`: options must be empty — `{}`, `null` or absent; anything else `ErrBadOptions`), `internal/server/inventory/service.go` (a `Compliance` field with interface `EvaluateDevice(ctx, deviceID) error`, called after `Groups`, same log-don't-fail rule), `internal/server/app/app.go` (construct the service, pass to inventory and both handlers as needed), the place sweeper jobs are registered (find with `grep -rn "sweeper.Job{" cmd internal`) — add job `compliance` every 15 minutes with a new unique `LockID`.

- [ ] Test (app package): assigning a compliance policy with non-empty options → 400; uploading inventory through the agent API triggers evaluation (result row appears). Commit `feat(server): wire compliance into inventory ingest and the sweeper`.

### Task 5: Admin API

**Files:** Create `internal/server/adminapi/compliance.go`, `internal/server/adminapi/dashboard.go`; modify `resources.go` (routes), the devices list JSON to add `compliance` (use `ComplianceOverall` over the page's device ids — one query per page). Tests in `internal/server/app/compliance_test.go`, `dashboard_test.go`.

- [ ] Endpoints exactly as spec §5 (except CSV — Task 6). Error mapping in the style of `writeAgentVersionError`. Tests: CRUD + roles (read-only admin can GET, not POST), device compliance endpoint, devices list field, dashboard numbers against a seeded fleet. Commit `feat(api): compliance policies, device compliance and the dashboard`.

### Task 6: CSV export

**Files:** Create `internal/server/adminapi/export.go` (+ a small `csvSafe(string) string`), tests `internal/server/app/export_test.go` and a unit test for `csvSafe`.

- [ ] Both endpoints per spec §5, streamed with `encoding/csv` (no whole-fleet buffering: page through devices 500 at a time). Tests: headers, Content-Disposition, row count, a hostname `=HYPERLINK(...)` comes out prefixed with `'`, read-only admin allowed. Commit `feat(api): CSV export of devices and compliance results`.

### Task 7: Console — overview, devices, device detail

**Files:** Create `web/src/pages/Overview.tsx/.css/.test.tsx`; modify `App.tsx` (`/` → Overview; unknown routes still → `/devices`), `components/Shell.tsx` (Overview first in nav), `pages/Devices.tsx` (compliance column + Export CSV link to `/api/admin/v1/devices/export.csv`), `pages/DeviceDetail.tsx` (compliance section from `/devices/{id}/compliance`), `api/types.ts`.

- [ ] Follow the existing pages' structure, tokens and `StatusDot`. Tests for each change. `npx vitest run` and `npx tsc --noEmit -p .` from `web/`. Commit `feat(console): overview dashboard and device compliance`.

### Task 8: Console — compliance page

**Files:** Create `web/src/pages/Compliance.tsx/.css/.test.tsx`; route `/compliance`; nav after Profiles.

- [ ] List with rollups, rule-row editor (all twelve types with typed inputs and inline validation matching server bounds), assign dialog (group + mode, no options), detail with state filter, Evaluate now, Export CSV. Tests: create sends the right rules JSON; each rule type renders its inputs; assign sends empty options; export link href. Commit `feat(console): compliance policies page`.

### Task 9: End to end, docs

**Files:** `test/e2e/e2e_test.go` (new `TestComplianceEndToEnd` per spec §7), `README.md` (a "Compliance" section after Configuration profiles, the dashboard and export in the relevant places), `docs/superpowers/plans/2026-09-12-roadmap.md` (M12 row; status line M1 through M12).

- [ ] Run the new e2e test. Commit `test(e2e): compliance end to end` and `docs: compliance, dashboard and export`.
