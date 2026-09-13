# M6 — Script Deployments Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A versioned script library, assigned to groups with options, that agents schedule and run for themselves, reporting every run.

**Architecture:** Scripts and immutable versions live server-side; assignments carry options as JSON. Check-in names the assigned script and version; the agent fetches each body once per version, decides locally when to run, executes through the existing executor, and posts runs back. Detection and remediation are two executions of one deployment, and detection's second run decides the outcome.

**Tech Stack:** Go 1.27, pgx/v5, PostgreSQL 17, bbolt, React 19 + TypeScript.

**Spec:** `docs/superpowers/specs/2026-09-13-m6-script-deployments-design.md`

## Global Constraints

- Module `retune`, Go 1.27. No new Go or npm dependencies.
- Postgres-backed tests use `storetest` and are skipped by `-short`; the Windows CI job runs `go test -short ./...`.
- Migration `0005_scripts` needs both `.up.sql` and `.down.sql`.
- Script output obeys `protocol.MaxOutputBytes` (1 MB per stream), capped by the agent and clamped again by the server, as command results already are.
- Every server mutation writes an audit entry in the same transaction, with the acting admin's email.
- `run_as: logged_in_user` is accepted and stored but never executed in M6; it reports `pending` with a reason.
- Windows-only agent code stays behind `//go:build windows` with a stub, so `go build ./...` passes on Linux.

---

## File Structure

**Created**

| File | Responsibility |
|---|---|
| `internal/server/store/migrations/0005_scripts.{up,down}.sql` | Tables and columns |
| `internal/server/store/scripts.go` | Script, version and run queries |
| `internal/server/scripts/service.go` | Library CRUD, versioning, run recording |
| `internal/server/scripts/options.go` | Assignment option parsing and validation |
| `internal/server/scripts/service_test.go` | Against Postgres |
| `internal/server/adminapi/scripts.go` | Library endpoints |
| `internal/agent/scripts/scheduler.go` | Decides what to run and when |
| `internal/agent/scripts/runner.go` | Detection and remediation execution |
| `internal/agent/scripts/scheduler_test.go` | Scheduling decisions, no I/O |
| `web/src/pages/Scripts.tsx`, `Scripts.css`, `Scripts.test.tsx` | Console |

**Modified**

| File | Change |
|---|---|
| `internal/protocol/v1.go` | `Item.Version`, `Item.Options` |
| `internal/protocol/scripts.go` (new) | Script fetch and run-report types |
| `internal/agent/state/state.go` | An `items` bucket with per-script state |
| `internal/agent/client/client.go` | `FetchScript`, `ReportScriptRun` |
| `internal/agent/session/session.go` | Hand `resp.Items` to the scheduler |
| `internal/agent/runner/runner.go` | Wire the scheduler |
| `internal/server/agentapi/handler.go` | Version fetch and run endpoints; item version and options on check-in |
| `internal/server/store/groups.go` | Carry `options` on assignments |
| `internal/server/adminapi/groups.go` | Accept options when assigning |
| `internal/server/app/app.go`, `adminapi/resources.go` | Wiring and routes |
| `web/src/api/types.ts`, `App.tsx`, `components/Shell.tsx` | Types, route, nav |
| `README.md` | Document deployments |

---

## Task 1: Schema and store

**Files:**
- Create: `internal/server/store/migrations/0005_scripts.{up,down}.sql`, `internal/server/store/scripts.go`
- Modify: `internal/server/store/groups.go` (assignment options)

**Interfaces:**
- Produces: `store.Script{ID, Name, Description, CurrentVersion, CreatedAt, UpdatedAt, CreatedBy}`; `store.ScriptVersion{ScriptID, Version, Body, DetectionBody, Hash, CreatedAt, CreatedBy}`; `store.ScriptRun{ID, ScriptID, Version, DeviceID, Status, Phase, Remediated, ExitCode, Stdout, Stderr, StdoutTruncated, StderrTruncated, Error, StartedAt, FinishedAt}`; on `*Queries`: `CreateScript`, `GetScript`, `ListScripts`, `UpdateScriptMeta`, `DeleteScript`, `CreateScriptVersion`, `GetScriptVersion`, `ListScriptVersions`, `InsertScriptRun`, `ListScriptRuns`, `LatestScriptRun`, `DeviceHasItem(ctx, deviceID, kind, itemID) (bool, error)`.
- `store.Assignment` gains `Options []byte`; `CreateAssignment`, `GetAssignment`, `ListAssignments` and `EffectiveItems` carry it. `store.Item` gains `Options []byte`.

- [ ] **Step 1: Write the migration**

Exactly the DDL in spec section 7. The down migration drops `script_runs`,
`script_versions`, `scripts` and the two added columns.

- [ ] **Step 2: Extend EffectiveItems to carry options and version**

`EffectiveItems` must return the options of the **most recently created include
assignment**, which is the conflict rule from the spec:

```sql
SELECT DISTINCT ON (a.item_kind, a.item_id) a.item_kind, a.item_id, a.options
FROM assignments a
JOIN group_members gm ON gm.group_id = a.group_id AND gm.device_id = $1
WHERE a.mode = 'include'
  AND NOT EXISTS (
      SELECT 1 FROM assignments x
      JOIN group_members gx ON gx.group_id = x.group_id AND gx.device_id = $1
      WHERE x.mode = 'exclude'
        AND x.item_kind = a.item_kind AND x.item_id = a.item_id)
ORDER BY a.item_kind, a.item_id, a.created_at DESC
```

- [ ] **Step 3: Write the store tests and implement**

Against `storetest.New(t)`: creating a script and three versions returns them
newest-first; `GetScriptVersion` on a missing version is `ErrNotFound`;
`DeviceHasItem` is true only for an assigned device; runs come back newest
first; deleting a script leaves its runs. Match the style of
`internal/server/store/commands.go`.

Run: `go test ./internal/server/store/ -run Script -count=1`

- [ ] **Step 4: Commit**

```bash
git add internal/server/store
git commit -m "feat(store): script library, versions and run history"
```

---

## Task 2: Option parsing

**Files:**
- Create: `internal/server/scripts/options.go`, and option tests in `internal/server/scripts/options_test.go`

**Interfaces:**
- Produces:

```go
// Options are the per-assignment settings of a script deployment.
type Options struct {
    Frequency         string `json:"frequency"`
    IntervalHours     int    `json:"interval_hours"`
    RunAs             string `json:"run_as"`
    TimeoutSeconds    int    `json:"timeout_seconds"`
    MaxRetries        int    `json:"max_retries"`
    RerunOnNewVersion bool   `json:"rerun_on_new_version"`
}

// DefaultOptions are applied to anything the caller leaves out.
func DefaultOptions() Options

// ParseOptions validates raw assignment options, filling in defaults.
func ParseOptions(raw []byte) (Options, error)
```

- [ ] **Step 1: Write the failing tests**

Empty input yields the defaults from spec section 4. `frequency: "hourly"` is
rejected naming the field. `interval_hours: 0` is rejected. `timeout_seconds`
outside 1–86400 is rejected. `run_as: "logged_in_user"` is **accepted** — it is
stored and handled later, not refused. Unknown keys are rejected, so a typo in
the console is not silently ignored.

- [ ] **Step 2: Implement**

Use `json.Decoder` with `DisallowUnknownFields`, then validate. Return errors
wrapping a package-level `ErrBadOptions` so the API can map them to 400.

Run: `go test ./internal/server/scripts/ -count=1`

- [ ] **Step 3: Commit**

```bash
git add internal/server/scripts
git commit -m "feat(scripts): assignment options with defaults and validation"
```

---

## Task 3: Script service

**Files:**
- Create: `internal/server/scripts/service.go`, `service_test.go`

**Interfaces:**
- Produces: `scripts.Service{Store, Now}` with `Create(ctx, NewScript) (store.Script, error)`, `Update(ctx, id, NewScript) (store.Script, error)` (writes a new version when a body changed), `Get`, `List`, `Delete`, `Version(ctx, id, version)`, `ListVersions`, `RecordRun(ctx, deviceID, run protocol.ScriptRun) error`.
- `scripts.ErrNotFound`, `scripts.ErrNameTaken`, `scripts.ErrBadRequest`.

- [ ] **Step 1: Write the failing tests**

Creating a script stores version 1. Editing only the description does **not**
create a version; editing the body does, and bumps `current_version`. Versions
are immutable: fetching version 1 after two edits still returns the original
body. `RecordRun` inserts a run and updates `device_item_status` to the run's
outcome with its version.

- [ ] **Step 2: Implement**

`Create` and `Update` run in one transaction with an audit entry
(`script.created`, `script.updated`, `script.deleted`). The hash is SHA-256 of
body and detection body, following `protocol.InventoryHash`'s approach.

`RecordRun` maps a run status onto an item status: `succeeded` →
`store.ItemSucceeded`, `failed` and `timed_out` → `store.ItemFailed`, and
writes both the run and the item status in one transaction.

Run: `go test ./internal/server/scripts/ -count=1`

- [ ] **Step 3: Commit**

```bash
git add internal/server/scripts
git commit -m "feat(scripts): library service with immutable versions"
```

---

## Task 4: Agent API

**Files:**
- Create: `internal/protocol/scripts.go`
- Modify: `internal/protocol/v1.go`, `internal/server/agentapi/handler.go`, `internal/server/app/app.go`

**Interfaces:**
- Produces:

```go
// ItemKindScript is the assignment kind for script deployments.
const ItemKindScript = "script"

// ScriptVersionResponse is the body of GET /scripts/{id}/versions/{version}.
type ScriptVersionResponse struct {
    Version       int    `json:"version"`
    Body          string `json:"body"`
    DetectionBody string `json:"detection_body"`
    Hash          string `json:"hash"`
}

// ScriptRun is POSTed to /scripts/{id}/runs.
type ScriptRun struct {
    Version         int       `json:"version"`
    Status          string    `json:"status"`
    Phase           string    `json:"phase"`
    Remediated      bool      `json:"remediated"`
    ExitCode        int       `json:"exit_code"`
    Stdout          string    `json:"stdout"`
    Stderr          string    `json:"stderr"`
    StdoutTruncated bool      `json:"stdout_truncated"`
    StderrTruncated bool      `json:"stderr_truncated"`
    Error           string    `json:"error"`
    StartedAt       time.Time `json:"started_at"`
    FinishedAt      time.Time `json:"finished_at"`
}

// Phases a run can be decided in.
const (
    PhaseScript      = "script"
    PhaseDetection   = "detection"
    PhaseRemediation = "remediation"
)
```

and on `Item`: `Version int`, `Options json.RawMessage`.

- [ ] **Step 1: Write the failing test**

In `internal/server/app`: a device assigned a script sees it on check-in with
its current version and options; `GET` on that version returns the body; `GET`
on a script the device is **not** assigned returns 404; posting a run records it
and moves the device's item status to succeeded.

- [ ] **Step 2: Implement the routes**

```go
mux.Handle("GET /api/agent/v1/scripts/{id}/versions/{version}", h.requireDevice(h.scriptVersion))
mux.Handle("POST /api/agent/v1/scripts/{id}/runs", h.requireDevice(h.scriptRun))
```

`scriptVersion` refuses unless `DeviceHasItem` says the script is assigned to
the calling device — a device may only read what it was given. Check-in fills
`Version` from the script's `current_version` and `Options` from the assignment.

- [ ] **Step 3: Run and commit**

```bash
go test ./internal/server/... -count=1
git add internal/protocol internal/server
git commit -m "feat(agent-api): fetch script versions and report runs"
```

---

## Task 5: Admin API and assignment options

**Files:**
- Create: `internal/server/adminapi/scripts.go`
- Modify: `internal/server/adminapi/groups.go`, `resources.go`

Routes:

```
GET    /api/admin/v1/scripts
POST   /api/admin/v1/scripts
GET    /api/admin/v1/scripts/{id}
POST   /api/admin/v1/scripts/{id}
DELETE /api/admin/v1/scripts/{id}
GET    /api/admin/v1/scripts/{id}/versions
GET    /api/admin/v1/scripts/{id}/runs        (optional device_id filter)
```

`POST /assignments` accepts an `options` object, validated by
`scripts.ParseOptions`, returning 400 with the offending field on bad input.

- [ ] **Step 1: Write the failing test**

Create a script over the API, assign it with options to a group, confirm the
options come back on the assignment listing, and confirm a read-only admin
cannot create or edit a script.

- [ ] **Step 2: Implement, run and commit**

```bash
go test ./internal/server/app/ -count=1
git add internal/server/adminapi
git commit -m "feat(admin-api): script library endpoints and assignment options"
```

---

## Task 6: Agent state and client

**Files:**
- Modify: `internal/agent/state/state.go`, `internal/agent/client/client.go`

**Interfaces:**
- Produces on `*state.Store`:

```go
// ItemState is what the agent remembers about one assigned item.
type ItemState struct {
    Version    int       `json:"version"`
    LastRunAt  time.Time `json:"last_run_at"`
    LastStatus string    `json:"last_status"`
    Failures   int       `json:"failures"`
}

func (s *Store) ItemState(id string) (ItemState, error)
func (s *Store) SetItemState(id string, st ItemState) error
func (s *Store) CachedScript(id string, version int) (protocol.ScriptVersionResponse, bool, error)
func (s *Store) CacheScript(id string, v protocol.ScriptVersionResponse) error
```

- Produces on `*client.Client`:

```go
func (c *Client) FetchScript(ctx context.Context, id string, version int) (protocol.ScriptVersionResponse, error)
func (c *Client) ReportScriptRun(ctx context.Context, id string, run protocol.ScriptRun) error
```

- [ ] **Step 1: Write the failing tests**

State: a missing item returns the zero value without error; setting and reading
round-trips; a cached script is returned only for the version it was stored
under. Add the two new buckets to the slice in `Open`.

- [ ] **Step 2: Implement, run and commit**

```bash
go test ./internal/agent/... -count=1
git add internal/agent
git commit -m "feat(agent): remember item state and cache script bodies"
```

---

## Task 7: The scheduler

**Files:**
- Create: `internal/agent/scripts/scheduler.go`, `runner.go`, `scheduler_test.go`

**Interfaces:**
- Produces:

```go
// Decision is what the scheduler concluded about one item.
type Decision struct {
    Run    bool
    Reason string // why not, when Run is false
    Status string // an item status to report instead of running, if any
}

// Decide reports whether an assigned script should run now.
func Decide(item protocol.Item, opts scripts.Options, st state.ItemState, now time.Time) Decision
```

`Decide` is a pure function, which is the point: every scheduling rule in spec
section 6 is unit-testable with no database, no filesystem and no clock.

```go
// Scheduler runs assigned scripts and reports the results.
type Scheduler struct {
    State  *state.Store
    Client Client        // FetchScript, ReportScriptRun
    Runner executor.Runner
    Log    *slog.Logger
    Now    func() time.Time
}

// Sync processes the items from one check-in. It returns when every script
// that needed to run has run.
func (s *Scheduler) Sync(ctx context.Context, items []protocol.Item) error
```

- [ ] **Step 1: Write the failing tests for Decide**

A table covering: a first run of `once`; a second check-in of the same version
not running again; a new version running when `rerun_on_new_version` is set and
not when it is clear; `recurring` running after its interval and not before;
`max_retries` reached on the same version blocking a run; a new version clearing
the failure count; and `run_as: logged_in_user` returning `Run: false` with
status `pending` and a reason that explains itself.

- [ ] **Step 2: Implement `Decide`, run the tests**

- [ ] **Step 3: Write the failing tests for detection and remediation**

With a fake `executor.Runner` recording invocations: no detection runs the body
once; detection exiting 0 runs the body **not at all** and reports succeeded;
detection exiting 1 runs the body then detection again, and the second
detection's exit code decides — 0 succeeds with `remediated: true`, non-zero
fails with phase `detection`.

- [ ] **Step 4: Implement `runner.go` and `Sync`**

`Sync` fetches and caches the body per version, runs at most one script at a
time, records the run locally before reporting it, updates `ItemState`, and
reports through the client. A failure to report leaves the state recorded so
the next check-in does not run it again.

- [ ] **Step 5: Run and commit**

```bash
go test ./internal/agent/scripts/ -count=1 -v
git add internal/agent/scripts
git commit -m "feat(agent): schedule and run assigned scripts"
```

---

## Task 8: Wire the agent

**Files:**
- Modify: `internal/agent/session/session.go`, `internal/agent/runner/runner.go`

- [ ] **Step 1: Hand items to the scheduler**

`session.Checkin` currently ignores `resp.Items`. After dispatching commands,
call the scheduler in the background so a long script does not hold up the
check-in, guarded so only one sync runs at a time.

- [ ] **Step 2: Verify the existing agent tests still pass, then commit**

```bash
go test ./internal/agent/... ./test/e2e/ -count=1
git add internal/agent
git commit -m "feat(agent): act on assigned scripts at check-in"
```

---

## Task 9: Console

**Files:**
- Create: `web/src/pages/Scripts.tsx`, `Scripts.css`, `Scripts.test.tsx`
- Modify: `web/src/api/types.ts`, `App.tsx`, `components/Shell.tsx`

- [ ] **Step 1: Write the failing tests**

The page lists scripts with their current version; the editor saves a body;
assigning to a group posts the options; the rollup shows counts and a run's
output.

- [ ] **Step 2: Implement**

Follow `Groups.tsx` and `Commands.tsx`: `useList`, the shared `ui` primitives,
a `.table-scroll` table, no new dependencies. The editor uses a monospace
textarea for the body and a second one for the optional detection script,
explaining in a hint what detection does.

- [ ] **Step 3: Run and commit**

```bash
npm --prefix web run test
git add web
git commit -m "feat(console): script library with versions and rollups"
```

---

## Task 10: Documentation and verification

- [ ] **Step 1: Document deployments in `README.md`**

What a deployment is and how it differs from an ad-hoc command; the options
table; how detection and remediation interact; and the plain statement that
`run_as: logged_in_user` is stored but not yet executed.

- [ ] **Step 2: Full suite**

```bash
go vet ./... && go test -count=1 ./... && npm --prefix web run test
```

- [ ] **Step 3: End-to-end against the Compose stack**

With a real agent on this machine: create a script, assign it to a group holding
the device, and watch the agent run it and report. Then edit the body and
confirm the new version runs again. Then add a detection script that exits 0 and
confirm the body is not run.

- [ ] **Step 4: Update the roadmap status line and finish the branch**

**REQUIRED SUB-SKILL:** Use superpowers:finishing-a-development-branch.

---

## Self-Review

**Spec coverage.** §3 library and versions → Tasks 1 and 3. §4 options → Task 2, with the API in Task 5. §5 what the agent is told → Task 4. §6 scheduling, detection and remediation → Task 7. §7 data model → Task 1. §8 console → Task 9. The `run_as` decision appears in Task 2 (accepted) and Task 7 (reported pending).

**Type consistency.** `scripts.Options` is defined in Task 2 and consumed by the API in Task 5 and the scheduler in Task 7. `protocol.ScriptRun` is defined in Task 4 and used by the client in Task 6, the scheduler in Task 7 and the service in Task 3. `state.ItemState` is defined in Task 6 and consumed by `Decide` in Task 7.

**Known risk.** Task 8 changes the check-in path every agent runs. The scheduler is called after commands are dispatched and its failures are logged rather than returned, so a broken deployment cannot stop check-ins, inventory or commands.
