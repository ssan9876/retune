# M5 — Groups and Assignments Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Devices belong to static and dynamic groups; items are assigned to groups with include and exclude; each device's effective set is computed on check-in.

**Architecture:** A hand-written lexer and recursive-descent parser turns a rule into an AST, which compiles to parameterized SQL against `devices` left-joined to `device_inventory`. Dynamic membership is materialized in `group_members`, refreshed on inventory change and by a 15-minute sweeper job. The effective set is one query, not a cache.

**Tech Stack:** Go 1.27, pgx/v5, PostgreSQL 17, React 19 + TypeScript.

**Spec:** `docs/superpowers/specs/2026-09-12-m5-groups-assignments-design.md`

## Global Constraints

- Module `retune`, Go 1.27. No new Go or npm dependencies; the parser is hand-written.
- Rule literals only ever reach SQL as `$n` placeholders. Field names come from a fixed allowlist map. Never build SQL by concatenating any part of user input.
- Rules are capped at 2000 characters and 20 levels of nesting, rejected at parse time.
- Every new table carries `tenant_id`, matching M1–M4.
- Postgres-backed tests use `storetest` and must be skipped by `-short`, because the Windows CI job runs `go test -short ./...`.
- Migration `0004_groups_assignments` needs both an `.up.sql` and a `.down.sql`, like 0001–0003.
- Group and assignment changes are audited, with the actor that made them.

---

## File Structure

**Created**

| File | Responsibility |
|---|---|
| `internal/server/store/migrations/0004_groups_assignments.{up,down}.sql` | Tables and the seeded built-in group |
| `internal/server/groups/lex.go` | Tokenizer |
| `internal/server/groups/parse.go` | Recursive-descent parser to an AST |
| `internal/server/groups/ast.go` | Node types and the field allowlist |
| `internal/server/groups/compile.go` | AST to parameterized SQL |
| `internal/server/groups/rule_test.go` | Parser and compiler tests, no database |
| `internal/server/groups/service.go` | Group CRUD and membership evaluation |
| `internal/server/groups/service_test.go` | Evaluation against Postgres |
| `internal/server/store/groups.go` | Group, member and assignment queries |
| `internal/server/store/itemstatus.go` | `device_item_status` and rollups |
| `internal/server/adminapi/groups.go` | Group, member, rule-preview and assignment endpoints |
| `web/src/pages/Groups.tsx`, `Groups.css` | Group list and editor |
| `web/src/pages/Groups.test.tsx` | Console tests |

**Modified**

| File | Change |
|---|---|
| `internal/server/sweeper/jobs.go` | A 15-minute `groups.evaluate` job |
| `internal/server/inventory/service.go` | Re-evaluate that device's dynamic membership after ingest |
| `internal/server/enroll/service.go` | Add a new device to the built-in group |
| `internal/protocol/v1.go` | `CheckinResponse.Items` |
| `internal/server/agentapi/handler.go` | Return the effective set on check-in |
| `internal/server/adminapi/handler.go` | Register the group routes |
| `internal/server/app/app.go` | Wire the groups service |
| `web/src/api/client.ts`, `web/src/components/Shell.tsx` | Group API calls and a nav entry |
| `README.md` | Document the rule language |

---

## Task 1: Schema

**Files:**
- Create: `internal/server/store/migrations/0004_groups_assignments.up.sql` and `.down.sql`

- [ ] **Step 1: Write the migration**

Exactly the DDL in spec section 7, plus the seeded built-in group:

```sql
INSERT INTO device_groups (id, tenant_id, name, description, kind, created_at, updated_at)
VALUES ('00000000-0000-0000-0000-000000000002',
        '00000000-0000-0000-0000-000000000001',
        'All devices', 'Every active device.', 'builtin', now(), now());
```

The down migration drops the four tables in reverse dependency order.

- [ ] **Step 2: Verify it applies**

Run: `go test ./internal/server/store/ -run Migrate -count=1`
Expected: PASS. If there is no such test, run `go test ./internal/server/store/ -count=1`, which opens a migrated database.

- [ ] **Step 3: Commit**

```bash
git add internal/server/store/migrations
git commit -m "feat(store): tables for groups, membership, assignments and item status"
```

---

## Task 2: Rule lexer and parser

**Files:**
- Create: `internal/server/groups/lex.go`, `parse.go`, `ast.go`, `rule_test.go`

**Interfaces:**
- Produces: `groups.Parse(rule string) (groups.Node, error)`; `groups.Node` implementations `And`, `Or`, `Not`, `Compare{Field, Op, Value}`, `HasSoftware{Name, Op, Version}`; `groups.ParseError{Offset int, Message string}` whose `Error()` reads `at offset N: message`.

- [ ] **Step 1: Write the failing tests**

```go
func TestParseAcceptsRealRules(t *testing.T) {
	for _, rule := range []string{
		`hostname LIKE 'DESKTOP-%'`,
		`ram_gb >= 16 AND os_version = 'Microsoft Windows 11 Pro'`,
		`NOT (manufacturer = 'ASRock' OR model = 'X')`,
		`has_software('7-Zip')`,
		`has_software('Google Chrome', '<', '120.0.0')`,
		`last_seen_days > 7 AND NOT hostname LIKE 'TEST-%'`,
		`HOSTNAME like 'a%'`, // keywords and fields are case-insensitive
		`hostname = 'it''s'`, // doubled quote escapes
	} {
		if _, err := groups.Parse(rule); err != nil {
			t.Errorf("Parse(%q) = %v", rule, err)
		}
	}
}

func TestParseRejects(t *testing.T) {
	cases := map[string]string{
		"unknown field":        `nope = 'x'`,
		"LIKE on a number":     `ram_gb LIKE '1%'`,
		"ordering on a string": `hostname > 'a'`,
		"string for a number":  `ram_gb = 'lots'`,
		"unclosed paren":       `(hostname = 'a'`,
		"unterminated string":  `hostname = 'a`,
		"empty":                ``,
		"trailing junk":        `hostname = 'a' bogus`,
		"bad arity":            `has_software('a', '<')`,
	}
	for name, rule := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := groups.Parse(rule); err == nil {
				t.Fatalf("Parse(%q) should have failed", rule)
			}
		})
	}
}

func TestParseReportsOffset(t *testing.T) {
	_, err := groups.Parse(`hostname = 'a' AND nope = 'b'`)
	var pe groups.ParseError
	if !errors.As(err, &pe) {
		t.Fatalf("want ParseError, got %v", err)
	}
	if pe.Offset != 19 {
		t.Errorf("offset = %d, want 19 (the start of `nope`)", pe.Offset)
	}
}

func TestParseRejectsOversizedRules(t *testing.T) {
	if _, err := groups.Parse(strings.Repeat("a", 2001)); err == nil {
		t.Error("a rule over 2000 characters should be rejected")
	}
	deep := strings.Repeat("(", 21) + "ram_gb = 1" + strings.Repeat(")", 21)
	if _, err := groups.Parse(deep); err == nil {
		t.Error("a rule nested over 20 deep should be rejected")
	}
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `go test ./internal/server/groups/ -v`
Expected: FAIL — no such package.

- [ ] **Step 3: Implement `ast.go`**

The node types above, plus the field table, which is the security boundary:

```go
type fieldKind int

const (
	stringField fieldKind = iota
	numberField
)

// fields is an allowlist: a rule can only ever name one of these, and the SQL
// on the right is the only thing that reaches the query. Literals are bound as
// placeholders, never interpolated.
var fields = map[string]struct {
	kind fieldKind
	sql  string
}{
	"hostname":       {stringField, "d.hostname"},
	"os_version":     {stringField, "d.os_version"},
	"os_build":       {stringField, "d.os_build"},
	"manufacturer":   {stringField, "d.manufacturer"},
	"model":          {stringField, "d.model"},
	"serial":         {stringField, "d.serial"},
	"agent_version":  {stringField, "d.agent_version"},
	"ram_gb":         {numberField, "coalesce(i.ram_gb, 0)"},
	"last_seen_days": {numberField, "floor(extract(epoch from ($CLOCK - d.last_seen_at)) / 86400)"},
}
```

`$CLOCK` is replaced by the clock placeholder number at compile time, so tests are deterministic.

- [ ] **Step 4: Implement `lex.go` and `parse.go`**

The tokenizer yields identifiers, operators, strings, numbers and parentheses with byte offsets. The parser is the grammar in spec section 3, one function per precedence level. Type checking happens as comparisons are built: string fields reject ordering operators, number fields reject `LIKE`, and a literal of the wrong type is an error naming the field.

- [ ] **Step 5: Run the tests**

Run: `go test ./internal/server/groups/ -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/server/groups
git commit -m "feat(groups): rule lexer and parser"
```

---

## Task 3: Rule compiler

**Files:**
- Create: `internal/server/groups/compile.go`
- Test: `internal/server/groups/rule_test.go`

**Interfaces:**
- Produces: `groups.Compile(n Node, tenantID uuid.UUID, now time.Time) (sql string, args []any, err error)` returning the full device-selecting query from spec section 7.

- [ ] **Step 1: Write the failing tests**

```go
func TestCompileBindsLiterals(t *testing.T) {
	n, err := groups.Parse(`hostname LIKE 'DESKTOP-%' AND ram_gb >= 16`)
	if err != nil {
		t.Fatal(err)
	}
	sql, args, err := groups.Compile(n, store.DefaultTenantID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sql, "DESKTOP-%") || strings.Contains(sql, "16") {
		t.Fatalf("literals must be bound, not interpolated: %s", sql)
	}
	if !slices.Contains(args, any("DESKTOP-%")) {
		t.Errorf("args %v should carry the pattern", args)
	}
}

func TestCompileIsInjectionProof(t *testing.T) {
	n, err := groups.Parse(`hostname = 'x''; DROP TABLE devices; --'`)
	if err != nil {
		t.Fatal(err)
	}
	sql, args, err := groups.Compile(n, store.DefaultTenantID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sql, "DROP TABLE") {
		t.Fatalf("the literal reached the SQL text: %s", sql)
	}
	if !slices.Contains(args, any("x'; DROP TABLE devices; --")) {
		t.Errorf("the literal should be an argument, got %v", args)
	}
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `go test ./internal/server/groups/ -run Compile -v`
Expected: FAIL — undefined `groups.Compile`.

- [ ] **Step 3: Implement the compiler**

A walker that appends to a `strings.Builder` and an `args` slice. Operators come from a fixed map, so an operator token can never reach the SQL as text from input. `has_software` compiles to the `EXISTS` form from spec section 7, with the version guard for ordering operators.

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/server/groups/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/server/groups
git commit -m "feat(groups): compile rules to parameterized SQL"
```

---

## Task 4: Store queries

**Files:**
- Create: `internal/server/store/groups.go`, `internal/server/store/itemstatus.go`

**Interfaces:**
- Produces: `store.Group{ID, TenantID, Name, Description, Kind, Rule, CreatedAt, UpdatedAt, EvaluatedAt *time.Time}`; `store.Assignment{ID, ItemKind, ItemID, GroupID, Mode, CreatedAt, CreatedBy}`; `store.ItemStatus{DeviceID, ItemKind, ItemID, Status, Detail, UpdatedAt}`; and on `*Queries`: `CreateGroup`, `GetGroup`, `ListGroups`, `UpdateGroup`, `DeleteGroup`, `SetGroupMembers(ctx, groupID, deviceIDs, now)`, `AddGroupMember`, `RemoveGroupMember`, `ListGroupMembers(ctx, groupID, page)`, `ListGroupsForDevice`, `DynamicGroups`, `CreateAssignment`, `DeleteAssignment`, `ListAssignments(ctx, itemKind, itemID)`, `EffectiveItems(ctx, deviceID)`, `SetItemStatus`, `ItemStatusRollup(ctx, itemKind, itemID)`.

- [ ] **Step 1: Write the failing test**

In `internal/server/store/groups_test.go`, against `storetest.New(t)`: create a static group, add two devices, list members, remove one, and confirm the count. Then create two assignments for one synthetic item kind — an include on the group holding the device and an exclude on another group also holding it — and assert `EffectiveItems` returns nothing, because exclude wins.

```go
func TestEffectiveItemsExcludeWins(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	dev := makeDevice(t, st)
	inc := makeGroupWith(t, st, "included", dev.ID)
	exc := makeGroupWith(t, st, "excluded", dev.ID)
	item := uuid.New()

	mustAssign(t, st, "script", item, inc.ID, "include")
	items, err := st.Q().EffectiveItems(ctx, dev.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("want the item included, got %v", items)
	}

	mustAssign(t, st, "script", item, exc.ID, "exclude")
	items, err = st.Q().EffectiveItems(ctx, dev.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Fatalf("exclude must win, got %v", items)
	}
}
```

- [ ] **Step 2: Run to verify it fails, implement, and re-run**

Run: `go test ./internal/server/store/ -run Group -count=1 -v`
Match the style of `internal/server/store/devices.go`: a `groupCols` constant, a `scanGroup` helper, `notFound(err)` on single-row reads, and `count(*) OVER ()` for paged lists as in `lists.go`.

- [ ] **Step 3: Commit**

```bash
git add internal/server/store
git commit -m "feat(store): group, assignment and item-status queries"
```

---

## Task 5: Group service and membership evaluation

**Files:**
- Create: `internal/server/groups/service.go`, `service_test.go`
- Modify: `internal/server/sweeper/jobs.go`, `internal/server/inventory/service.go`, `internal/server/enroll/service.go`

**Interfaces:**
- Produces: `groups.Service{Store, Now}` with `Create`, `Update`, `Delete`, `Get`, `List`, `AddMember`, `RemoveMember`, `Preview(ctx, rule string) ([]store.Device, error)`, `EvaluateGroup(ctx, g store.Group) (int, error)`, `EvaluateAll(ctx) (int, error)`, `EvaluateDevice(ctx, deviceID uuid.UUID) error`.

- [ ] **Step 1: Write the failing test**

Against Postgres: two devices, one with `ram_gb` 32 and one with 8; a dynamic group whose rule is `ram_gb >= 16`; `EvaluateGroup` puts exactly the first in the group. Then change the inventory of the second to 64 and call `EvaluateDevice`, and assert it joins. Then assert the built-in group holds every active device after `EvaluateAll`.

- [ ] **Step 2: Implement**

`EvaluateGroup` parses and compiles the rule, runs the query, and calls `SetGroupMembers` inside one transaction, so a group is never observed half-evaluated. `EvaluateDevice` re-evaluates only the groups that could change for one device: every dynamic group, plus the built-in one. A rule that no longer parses — possible only if a rule was stored before a grammar change — logs and leaves membership untouched rather than emptying the group.

- [ ] **Step 3: Wire the triggers**

- `internal/server/inventory/service.go`: after a successful ingest, call `EvaluateDevice`. A failure there is logged, not returned: inventory has already been stored, and failing the agent's request would make it retry a write that succeeded.
- `internal/server/enroll/service.go`: add the new device to the built-in group.
- `internal/server/sweeper/jobs.go`: a `groups.evaluate` job, lock ID 5274003, `Interval: 15 * time.Minute` regardless of the configured sweep interval, calling `EvaluateAll`.

- [ ] **Step 4: Run the tests and commit**

```bash
go test ./internal/server/... -count=1
git add internal/server
git commit -m "feat(groups): evaluate dynamic membership on inventory, enrollment and a timer"
```

---

## Task 6: Effective set on check-in

**Files:**
- Modify: `internal/protocol/v1.go`, `internal/server/agentapi/handler.go`

- [ ] **Step 1: Add the protocol field**

```go
// Item is one thing assigned to this device. Kinds arrive in later
// milestones; an agent ignores a kind it does not know.
type Item struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}
```

with `Items []Item \`json:"items,omitempty"\`` on `CheckinResponse`.

- [ ] **Step 2: Return it from check-in**

`h.Store.Q().EffectiveItems(ctx, device.ID)` in the check-in handler, mapped into the response.

- [ ] **Step 3: Test**

Extend the existing check-in test: a device in a group with an include assignment sees the item in its check-in response.

- [ ] **Step 4: Commit**

```bash
git add internal/protocol internal/server/agentapi
git commit -m "feat(agent-api): return the effective item set on check-in"
```

---

## Task 7: Admin API

**Files:**
- Create: `internal/server/adminapi/groups.go`
- Modify: `internal/server/adminapi/handler.go`, `internal/server/app/app.go`

Routes, following the existing read/write middleware split:

```
GET    /api/admin/v1/groups
POST   /api/admin/v1/groups
GET    /api/admin/v1/groups/{id}
POST   /api/admin/v1/groups/{id}              update (the console's api client
                                              has only get/post/del, so update
                                              is a POST rather than a PATCH)
DELETE /api/admin/v1/groups/{id}
GET    /api/admin/v1/groups/{id}/members
POST   /api/admin/v1/groups/{id}/members      {device_id}
DELETE /api/admin/v1/groups/{id}/members/{deviceID}
POST   /api/admin/v1/groups/preview           {rule} -> matching devices and a count
POST   /api/admin/v1/groups/{id}/evaluate     re-evaluate now
GET    /api/admin/v1/assignments?item_kind=&item_id=
POST   /api/admin/v1/assignments              {item_kind, item_id, group_id, mode}
DELETE /api/admin/v1/assignments/{id}
GET    /api/admin/v1/items/{kind}/{id}/status rollup counts
```

- [ ] **Step 1: Write the failing test**

In the existing admin API test style: create a dynamic group over the API, preview a rule, confirm a bad rule returns `400` with the offset in the message, and confirm a read-only admin cannot create a group.

- [ ] **Step 2: Implement and run**

Editing a static group's members is allowed; editing a dynamic or built-in group's members returns `409` with an explanation, because membership there is derived. Changing a rule re-evaluates the group before returning, so the caller sees the new membership immediately.

- [ ] **Step 3: Commit**

```bash
git add internal/server/adminapi internal/server/app
git commit -m "feat(admin-api): group, membership and assignment endpoints"
```

---

## Task 8: Console

**Files:**
- Create: `web/src/pages/Groups.tsx`, `Groups.css`, `Groups.test.tsx`
- Modify: `web/src/api/client.ts`, `web/src/components/Shell.tsx`, `web/src/main.tsx` (routes)

- [ ] **Step 1: Write the failing test**

Mirroring `web/src/pages/Devices.test.tsx`: the page lists groups; creating a dynamic group shows the live preview count; an invalid rule shows the parse error under the editor.

- [ ] **Step 2: Implement**

A list of groups with kind and member count, and an editor where a dynamic group's rule is typed. The rule editor previews against the API as the administrator types, debounced, showing either "matches N devices" with a sample or the parse error at its offset. Static groups get a device picker instead. Follow the existing token and design conventions; no new dependencies.

- [ ] **Step 3: Run the tests and commit**

```bash
npm --prefix web run test
git add web
git commit -m "feat(console): groups page with a live rule preview"
```

---

## Task 9: Documentation and verification

- [ ] **Step 1: Document the rule language in `README.md`**

The grammar, the field table, and worked examples, plus the note that versions which are not dotted-numeric do not match ordering comparisons.

- [ ] **Step 2: Full suite**

Run: `go vet ./... && go test -count=1 ./... && npm --prefix web run test`

- [ ] **Step 3: End-to-end**

Against the Compose stack with a real enrolled agent: create a dynamic group matching that machine, confirm it appears in the members list, assign a synthetic item to the group, and confirm the item comes back in the agent's check-in response.

- [ ] **Step 4: Update the roadmap status line and finish the branch**

**REQUIRED SUB-SKILL:** Use superpowers:finishing-a-development-branch.

---

## Self-Review

**Spec coverage.** §3 rule language → Tasks 2 and 3. §4 groups and the three evaluation triggers → Tasks 4 and 5. §5 assignments and the effective set → Tasks 4 and 6. §6 item status → Tasks 4 and 7. §7 data model → Task 1. §2's console decision → Task 8.

**Type consistency.** `groups.Parse` returns `groups.Node`, consumed by `groups.Compile` in Task 3 and `groups.Service` in Task 5. `store.EffectiveItems` is defined in Task 4 and consumed in Task 6. The sweeper `Job` shape matches the one M4 built.

**Known risk.** Task 5 changes the inventory ingest path, which every agent hits. The evaluation failure is deliberately non-fatal there; the existing inventory tests guard the ingest itself.
