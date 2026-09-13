# M9 Application Deployment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an administrator assign a winget package to a group and have the agent install it, notice when it goes missing, and remove it when told to.

**Architecture:** A new assignable item kind, `app`, alongside the existing `script` and `profile` kinds. The server stores apps as immutable versions and tracks per-device install status; the agent drives `winget.exe` as LocalSystem, decides what to do with a pure function, and reports terminal results. Install and uninstall are an *intent* recorded on the assignment, so falling out of a group never removes software.

**Tech Stack:** Go 1.27, pgx/v5 + pgxpool, golang-migrate (embedded, `pgx5://`), testcontainers-go, UUIDv7, bbolt, React 19 + TypeScript + Vite, vitest + Testing Library.

**Spec:** `docs/superpowers/specs/2026-09-13-m9-app-deployment-design.md`

## Global Constraints

These apply to every task. They are copied from the spec; where a task repeats one it is for emphasis, not because the others are exempt.

- **winget is invoked only as:** `--exact --source winget --disable-interactivity --accept-source-agreements`, with install additionally passing `--scope machine --silent --accept-package-agreements`. Never omit `--source winget`: the `msstore` source prompts for an agreement and sends the machine's geographic region upstream.
- **winget output is decoded as UTF-8 explicitly.** The default decoding mangles it (`©` arrives as `┬⌐`).
- **Exit code `-1978335212`** (`APPINSTALLER_CLI_ERROR_NO_APPLICATIONS_FOUND`) means "not installed". It is the detection signal, not a failure.
- **Scope is `machine` only.** `user` is rejected by validation. The agent is LocalSystem, so a user-scope install would land in the SYSTEM account's profile.
- **Retune never upgrades an app it did not install this version of.** No chasing new upstream releases.
- **Only terminal statuses are reported:** `succeeded` and `failed`. Both are already in the `device_item_status` CHECK constraint, so no migration touches the shared tables. Apps are never `pending`: unlike a run-as-user script, the server cannot tell from a check-in whether an install will work, so every app status comes from a result the agent reported.
- **Local agent state is written before a result is reported**, so an unreachable server never causes a reinstall.
- **Every server-side mutation writes a `store.AuditEntry` in the same transaction** as the change.
- **Comments explain why, not what.** Match the density and voice of the surrounding code.
- **Go:** `gofmt -w`, `go vet ./...`, and `GOOS=linux go build ./...` must pass. Windows-only code goes behind `//go:build windows` with a matching `_other.go` stub.

## File Structure

**New files:**

| File | Responsibility |
|---|---|
| `internal/protocol/app.go` | `ItemKindApp`, `AppOptions`, `ParseAppOptions`, `AppVersionResponse`, `AppResult` |
| `internal/protocol/app_test.go` | Options defaults, bounds, unknown-field rejection |
| `internal/server/store/migrations/0008_apps.up.sql` | `apps`, `app_versions`, `app_installs` |
| `internal/server/store/migrations/0008_apps.down.sql` | Drops the three tables |
| `internal/server/store/apps.go` | Queries for the three tables |
| `internal/server/apps/service.go` | CRUD, immutable versions, `RecordInstall`, audit |
| `internal/server/apps/service_test.go` | Service behaviour against real Postgres |
| `internal/server/adminapi/apps.go` | The `/apps` admin handlers |
| `internal/server/adminapi/itemkinds.go` | The kind → options-parser registry (Task 1) |
| `internal/agent/apps/winget.go` | Building command lines and classifying exit codes, portable so it is unit-tested everywhere |
| `internal/agent/apps/winget_windows.go` | Locating `winget.exe` and running it |
| `internal/agent/apps/winget_other.go` | The non-Windows stub, returning `ErrNoAppInstaller` |
| `internal/agent/apps/winget_test.go` | Command construction and exit-code classification |
| `internal/agent/apps/scheduler.go` | The pure `Decide` |
| `internal/agent/apps/scheduler_test.go` | `Decide` as a table |
| `internal/agent/apps/syncer.go` | `Sync`, one install at a time, reporting |
| `internal/agent/apps/syncer_test.go` | End-to-end against a fake winget |
| `web/src/pages/Apps.tsx` | List, editor, assign dialog, detail |
| `web/src/pages/Apps.css` | Page styles |
| `web/src/pages/Apps.test.tsx` | Console behaviour |

**Modified files:**

| File | Change |
|---|---|
| `internal/server/adminapi/groups.go` | `createAssignment` uses the parser registry; unknown kinds 400 |
| `internal/server/agentapi/handler.go` | Kind → version-resolver registry; `/apps` agent routes |
| `internal/server/adminapi/resources.go` | Mount the `/apps` routes |
| `internal/server/app/app.go` | Construct `apps.Service` and inject it |
| `internal/agent/session/session.go` | `ItemSyncer` interface and a slice of them |
| `internal/agent/runner/runner.go` | Construct the app syncer |
| `internal/agent/state/state.go` | An `apps` bucket, `AppState`, and its accessors |
| `web/src/App.tsx`, `web/src/components/Shell.tsx` | Route and nav entry |
| `web/src/api/types.ts` | `App`, `AppVersion`, `AppInstall` |
| `README.md` | An "Applications" section |
| `docs/superpowers/plans/2026-09-12-roadmap.md` | M9 row and status |

---

### Task 1: One registry for assignment options

Today `createAssignment` switches on `req.ItemKind` with **no `default`**. An assignment naming a kind nobody implements is accepted and silently stored with empty options. This task fixes that and gives the third kind somewhere to register.

**Files:**
- Create: `internal/server/adminapi/itemkinds.go`
- Modify: `internal/server/adminapi/groups.go` — the options block inside `createAssignment`
- Test: `internal/server/app/groups_test.go`

**Interfaces:**
- Consumes: `protocol.ParseDeploymentOptions([]byte) (DeploymentOptions, error)`, `protocol.ProfileOptions`, `protocol.ItemKindScript`, `protocol.ItemKindProfile`, `protocol.ErrBadOptions`.
- Produces: `adminapi.optionsParsers`, a `map[string]func(json.RawMessage) ([]byte, error)`. Task 7 adds the `protocol.ItemKindApp` entry.

- [ ] **Step 1: Write the failing test**

Add to `internal/server/app/groups_test.go`:

```go
// An assignment naming a kind nothing implements is refused. It used to be
// accepted and stored with empty options, so a typo produced an assignment
// that could never do anything and never said why.
func TestAssignmentRejectsAnUnknownItemKind(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)

	status, body := admin.do(http.MethodPost, "/assignments", map[string]any{
		"item_kind": "widget",
		"item_id":   uuid.Must(uuid.NewV7()).String(),
		"group_id":  "00000000-0000-0000-0000-000000000002",
		"mode":      "include",
	})
	if status != http.StatusBadRequest {
		t.Fatalf("want 400, got %d %s", status, body)
	}
	if !strings.Contains(string(body), "widget") {
		t.Errorf("the error should name the kind, got %s", body)
	}
}

// An exclude assignment carries no options, so it is accepted whatever the
// kind: it only takes something away.
func TestExcludeAssignmentNeedsNoOptions(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)

	status, body := admin.do(http.MethodPost, "/assignments", map[string]any{
		"item_kind": "widget",
		"item_id":   uuid.Must(uuid.NewV7()).String(),
		"group_id":  "00000000-0000-0000-0000-000000000002",
		"mode":      "exclude",
	})
	if status != http.StatusCreated {
		t.Fatalf("want 201, got %d %s", status, body)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/server/app/ -run 'AssignmentRejects|ExcludeAssignmentNeeds' -count=1`

Expected: `TestAssignmentRejectsAnUnknownItemKind` FAILs with `want 400, got 201`.

- [ ] **Step 3: Write the registry**

Create `internal/server/adminapi/itemkinds.go`:

```go
package adminapi

import (
	"encoding/json"
	"fmt"

	"retune/internal/protocol"
)

// optionsParsers validates and canonicalises the options of an include
// assignment, by item kind. A kind that is not here is one this server does
// not implement: an assignment naming it could never do anything, so it is
// refused rather than stored.
var optionsParsers = map[string]func(json.RawMessage) ([]byte, error){
	protocol.ItemKindScript: func(raw json.RawMessage) ([]byte, error) {
		opts, err := protocol.ParseDeploymentOptions(raw)
		if err != nil {
			return nil, err
		}
		return opts.Marshal()
	},
	protocol.ItemKindProfile: func(raw json.RawMessage) ([]byte, error) {
		var opts protocol.ProfileOptions
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &opts); err != nil {
				return nil, fmt.Errorf("%w: profile options must be an object", protocol.ErrBadOptions)
			}
		}
		return json.Marshal(opts)
	},
}
```

- [ ] **Step 4: Use it in createAssignment**

In `internal/server/adminapi/groups.go`, replace the whole block that begins `var options []byte` and contains `switch req.ItemKind { ... }` with:

```go
	// Options are validated here so an agent never has to defend itself
	// against nonsense. An exclude assignment carries none: it only takes
	// something away, whatever the kind.
	var options []byte
	if req.Mode == store.ModeInclude {
		parse, known := optionsParsers[req.ItemKind]
		if !known {
			writeError(w, http.StatusBadRequest, "bad_request",
				fmt.Sprintf("there is no such item kind as %q", req.ItemKind))
			return
		}
		encoded, err := parse(req.Options)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_options", err.Error())
			return
		}
		options = encoded
	}
```

Add `"fmt"` to that file's imports if it is not already there. Run `go vet` afterwards and remove `"encoding/json"` or the `protocol` import from `groups.go` only if it reports them unused — other functions in the file may still need them.

- [ ] **Step 5: Run the tests**

Run: `go test ./internal/server/app/ ./internal/server/adminapi/ -count=1`

Expected: PASS, including both new tests and every existing assignment test.

- [ ] **Step 6: Commit**

```bash
git add internal/server/adminapi/itemkinds.go internal/server/adminapi/groups.go internal/server/app/groups_test.go
git commit -m "fix: refuse an assignment naming an item kind nothing implements"
```

---

### Task 2: One dispatcher for check-in item versions

`checkin` resolves each item's current version with two sequential `if it.Kind == ...` blocks, which also drop items whose script or profile has been deleted. A third kind would reach agents with `Version: 0` and no existence check.

**Files:**
- Modify: `internal/server/agentapi/handler.go` — add `itemVersion`, rewrite the loop in `checkin`
- Test: `internal/server/app/scripts_test.go`

**Interfaces:**
- Consumes: `h.Store.Q().GetScript(ctx, uuid.UUID)`, `h.Profiles.Get(ctx, uuid.UUID)`, `store.Item{Kind string, ID uuid.UUID, Options []byte}`.
- Produces: `func (h *Handler) itemVersion(ctx context.Context, it store.Item) (int, bool)`. Task 8 adds the `app` case.

- [ ] **Step 1: Write the failing test**

Add to `internal/server/app/scripts_test.go`:

```go
// An item of a kind this server does not implement is never handed to an
// agent. There is no endpoint to fetch its content from and no version to
// fetch, so sending it could only confuse.
func TestCheckinDropsAnUnknownItemKind(t *testing.T) {
	a, srv := newTestApp(t)
	_, agent := enrollDevice(t, a, srv, "DESKTOP-UNKNOWNKIND")

	// Written straight to the store, because the admin API now refuses it.
	err := a.Store.Q().CreateAssignment(context.Background(), store.Assignment{
		ID: uuid.Must(uuid.NewV7()), ItemKind: "widget", ItemID: uuid.Must(uuid.NewV7()),
		GroupID: uuid.MustParse("00000000-0000-0000-0000-000000000002"),
		Mode:    store.ModeInclude, CreatedAt: time.Now(), CreatedBy: "test",
	})
	if err != nil {
		t.Fatal(err)
	}

	status, body := send(t, agent, http.MethodPost, srv.URL+"/api/agent/v1/checkin",
		protocol.CheckinRequest{AgentVersion: "1.0.0"})
	if status != http.StatusOK {
		t.Fatalf("checkin: %d %s", status, body)
	}
	if items := decodeJSON[protocol.CheckinResponse](t, body).Items; len(items) != 0 {
		t.Fatalf("a kind nothing implements must not be sent, got %+v", items)
	}
}
```

If `store.Assignment`'s field names differ from the above, read `internal/server/store/groups.go` and use the real ones rather than guessing.

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/server/app/ -run TestCheckinDropsAnUnknownItemKind -count=1`

Expected: FAIL — one item comes back, carrying `Version: 0`.

- [ ] **Step 3: Add the dispatcher**

In `internal/server/agentapi/handler.go`, add:

```go
// itemVersion reports the current version of an assigned item, and whether it
// still exists. A kind with no case here is one this server does not
// implement, and is never offered to an agent.
func (h *Handler) itemVersion(ctx context.Context, it store.Item) (int, bool) {
	switch it.Kind {
	case protocol.ItemKindScript:
		// The agent needs the version to know whether its cached copy is
		// current; it fetches the body separately, once per version.
		sc, err := h.Store.Q().GetScript(ctx, it.ID)
		if err != nil {
			// A script that has gone missing is simply not offered.
			h.Log.Warn("assigned script is missing", "script_id", it.ID, "error", err)
			return 0, false
		}
		return sc.CurrentVersion, true
	case protocol.ItemKindProfile:
		pr, err := h.Profiles.Get(ctx, it.ID)
		if err != nil {
			h.Log.Warn("assigned profile is missing", "profile_id", it.ID, "error", err)
			return 0, false
		}
		return pr.CurrentVersion, true
	}
	return 0, false
}
```

- [ ] **Step 4: Rewrite the loop in checkin**

Replace the entire `for _, it := range assigned { ... }` loop with:

```go
	for _, it := range assigned {
		version, exists := h.itemVersion(ctx, it)
		if !exists {
			continue
		}
		items = append(items, protocol.Item{
			Kind: it.Kind, ID: it.ID.String(), Version: version, Options: it.Options,
		})

		// A deployment that needs a signed-in user cannot run on a machine
		// where nobody is. The check-in says who is signed in, so the server
		// records that as pending; the agent still receives it, and reports a
		// real result as soon as somebody signs in.
		if it.Kind != protocol.ItemKindScript || strings.TrimSpace(req.LoggedInUser) != "" {
			continue
		}
		opts, err := protocol.ParseDeploymentOptions(it.Options)
		if err != nil || !opts.NeedsUserSession() {
			continue
		}
		if err := h.Scripts.SetItemPending(ctx, a.Device.ID, it.ID, version,
			"waiting for somebody to sign in"); err != nil {
			h.Log.Warn("record pending deployment", "script_id", it.ID, "error", err)
		}
	}
```

- [ ] **Step 5: Run the tests**

Run: `go test ./internal/server/app/ ./test/e2e/ -count=1`

Expected: PASS, including `TestRunAsUserIsPendingUntilSomebodySignsIn` and `TestItemStatusCarriesTheVersion` — both exercise this loop.

- [ ] **Step 6: Commit**

```bash
git add internal/server/agentapi/handler.go internal/server/app/scripts_test.go
git commit -m "refactor: resolve check-in item versions through one dispatcher"
```

---

### Task 3: Agent dispatch through a list of syncers

`Session.Checkin` hands the item slice to two hardwired fields, with the "run when the list is empty" difference written out as two branches. A third subsystem would be a third branch, and the reason for the difference would stay implicit.

**Files:**
- Modify: `internal/agent/session/session.go` — `Config`, `New`, `Checkin`, plus two adapter types
- Test: `internal/agent/session/session_test.go`

**Interfaces:**
- Produces:
  ```go
  type ItemSyncer interface {
      Sync(ctx context.Context, items []protocol.Item) error
      RunOnEmpty() bool
      Name() string
  }
  ```
  and `Config.Syncers []ItemSyncer`. `Config.Scripts` and `Config.Policy` stay exactly as they are — `New` still wires their clients and now also appends them to `Syncers`. Task 11 appends the app syncer.

- [ ] **Step 1: Write the failing test**

Read `internal/agent/session/session_test.go` first and follow however it already builds a session and waits for background work; the waiting involves the `s.pending` WaitGroup. Then add:

```go
// A syncer that runs on empty is called with nothing assigned; one that does
// not is left alone. That difference is the whole reason profiles can revert.
func TestCheckinCallsSyncersByTheirEmptyRule(t *testing.T) {
	eager := &countingSyncer{name: "eager", onEmpty: true}
	lazy := &countingSyncer{name: "lazy"}

	s := newTestSession(t, func(c *session.Config) {
		c.Syncers = []session.ItemSyncer{eager, lazy}
	})
	if _, err := s.Checkin(context.Background()); err != nil {
		t.Fatal(err)
	}
	s.Wait()

	if eager.calls() != 1 {
		t.Errorf("a syncer that runs on empty should have been called once, got %d", eager.calls())
	}
	if lazy.calls() != 0 {
		t.Errorf("a syncer that does not should have been left alone, got %d", lazy.calls())
	}
}

type countingSyncer struct {
	name    string
	onEmpty bool
	mu      sync.Mutex
	n       int
}

func (c *countingSyncer) Sync(context.Context, []protocol.Item) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n++
	return nil
}
func (c *countingSyncer) RunOnEmpty() bool { return c.onEmpty }
func (c *countingSyncer) Name() string     { return c.name }
func (c *countingSyncer) calls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}
```

If there is no `newTestSession` helper and no exported way to wait, add both: a helper that builds a `Session` against an `httptest` server the way the existing tests do, and `func (s *Session) Wait() { s.pending.Wait() }` on `Session` with the comment that it exists so tests can wait for background syncers.

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/agent/session/ -run TestCheckinCallsSyncersByTheirEmptyRule -count=1`

Expected: FAIL to compile — `session.ItemSyncer` and `Config.Syncers` do not exist.

- [ ] **Step 3: Add the interface, the field and the adapters**

In `internal/agent/session/session.go`:

```go
// ItemSyncer applies one kind of assigned work. The agent hands every syncer
// the whole item list and each filters it, so a kind nobody handles is simply
// ignored.
type ItemSyncer interface {
	Sync(ctx context.Context, items []protocol.Item) error
	// RunOnEmpty reports whether Sync must be called even when nothing is
	// assigned. Profiles say yes: an empty list is exactly when a profile that
	// has just been unassigned must be undone.
	RunOnEmpty() bool
	// Name identifies the subsystem in the agent's log.
	Name() string
}
```

Add to `Config`:

```go
	// Syncers apply what is assigned to this device. New appends Scripts and
	// Policy to whatever is set here.
	Syncers []ItemSyncer
```

Add next to the existing `scriptClient` and `policyClient` types:

```go
// scriptSyncer adapts the script scheduler. It is not called with an empty
// item list: a script that is no longer assigned simply stops running.
type scriptSyncer struct{ s *scripts.Scheduler }

func (a scriptSyncer) Sync(ctx context.Context, items []protocol.Item) error {
	return a.s.Sync(ctx, items)
}
func (scriptSyncer) RunOnEmpty() bool { return false }
func (scriptSyncer) Name() string     { return "assigned scripts" }

// policySyncer adapts the profile reconciler, which must run on an empty list:
// that is exactly when a profile that has just been unassigned is undone.
type policySyncer struct{ s *policy.Syncer }

func (a policySyncer) Sync(ctx context.Context, items []protocol.Item) error {
	return a.s.Sync(ctx, items)
}
func (policySyncer) RunOnEmpty() bool { return true }
func (policySyncer) Name() string     { return "configuration profiles" }
```

At the end of `New`, after the existing `cfg.Scripts` and `cfg.Policy` client wiring and before `return s, nil`:

```go
	if cfg.Scripts != nil {
		s.cfg.Syncers = append(s.cfg.Syncers, scriptSyncer{cfg.Scripts})
	}
	if cfg.Policy != nil {
		s.cfg.Syncers = append(s.cfg.Syncers, policySyncer{cfg.Policy})
	}
```

Append to `s.cfg`, not `cfg`: `s` was built from a copy of the config, and the client wiring above mutates `cfg` before that copy is taken.

- [ ] **Step 4: Replace the two branches in Checkin**

Replace both the `if s.cfg.Scripts != nil && len(resp.Items) > 0 { ... }` block and the `if s.cfg.Policy != nil { ... }` block with:

```go
	// Assigned work is applied in the background: a long-running deployment
	// must not hold up check-ins, inventory or commands. Each syncer runs one
	// job at a time internally, so a slow one only means the next check-in
	// finds it still busy.
	for _, syncer := range s.cfg.Syncers {
		if len(resp.Items) == 0 && !syncer.RunOnEmpty() {
			continue
		}
		items, syncer := resp.Items, syncer
		s.pending.Add(1)
		go func() {
			defer s.pending.Done()
			if err := syncer.Sync(ctx, items); err != nil {
				s.cfg.Log.Warn("applying assigned work failed", "syncer", syncer.Name(), "error", err)
			}
		}()
	}
```

- [ ] **Step 5: Run the tests**

Run: `go test ./internal/agent/... -count=1 && go vet ./... && GOOS=linux go build ./...`

Expected: PASS. The existing script and profile sync tests are the real check here — they must behave exactly as before.

- [ ] **Step 6: Commit**

```bash
git add internal/agent/session/session.go internal/agent/session/session_test.go
git commit -m "refactor: dispatch assigned work through a list of syncers"
```

---

### Task 4: The app protocol

**Files:**
- Create: `internal/protocol/app.go`
- Create: `internal/protocol/app_test.go`

**Interfaces:**
- Produces, for every later task:
  ```go
  const ItemKindApp = "app"
  const (IntentInstall = "install"; IntentUninstall = "uninstall")
  const (ScopeMachine = "machine")
  const (MinAppTimeoutSeconds = 60; MaxAppTimeoutSeconds = 14400)

  type AppOptions struct {
      Intent         string `json:"intent"`
      TimeoutSeconds int    `json:"timeout_seconds"`
  }
  func DefaultAppOptions() AppOptions
  func ParseAppOptions(raw []byte) (AppOptions, error)
  func (o AppOptions) Timeout() time.Duration
  func (o AppOptions) Marshal() ([]byte, error)

  type AppVersionResponse struct {
      Version       int    `json:"version"`
      PackageID     string `json:"package_id"`
      PinnedVersion string `json:"pinned_version"`
      Scope         string `json:"scope"`
      InstallArgs   string `json:"install_args"`
      Hash          string `json:"hash"`
  }

  type AppResult struct {
      Version          int       `json:"version"`
      Intent           string    `json:"intent"`
      Status           string    `json:"status"`
      InstalledVersion string    `json:"installed_version"`
      ExitCode         int       `json:"exit_code"`
      Stdout           string    `json:"stdout"`
      Stderr           string    `json:"stderr"`
      StdoutTruncated  bool      `json:"stdout_truncated"`
      StderrTruncated  bool      `json:"stderr_truncated"`
      Error            string    `json:"error"`
      Detail           string    `json:"detail"`
      StartedAt        time.Time `json:"started_at"`
      FinishedAt       time.Time `json:"finished_at"`
  }
  ```
  `Status` carries `ResultSucceeded` or `ResultFailed`, the constants the script protocol already defines.

- [ ] **Step 1: Write the failing test**

Create `internal/protocol/app_test.go`:

```go
package protocol_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"retune/internal/protocol"
)

func TestAppOptionsDefaults(t *testing.T) {
	for _, raw := range []string{"", "{}", "null"} {
		o, err := protocol.ParseAppOptions([]byte(raw))
		if err != nil {
			t.Fatalf("ParseAppOptions(%q): %v", raw, err)
		}
		if o.Intent != protocol.IntentInstall {
			t.Errorf("intent = %q, want install: an assignment means put it there", o.Intent)
		}
		if o.TimeoutSeconds != 900 {
			t.Errorf("timeout = %d, want 900", o.TimeoutSeconds)
		}
		if o.Timeout() != 15*time.Minute {
			t.Errorf("Timeout() = %v, want 15m", o.Timeout())
		}
	}
}

func TestAppOptionsRejectsNonsense(t *testing.T) {
	cases := map[string]string{
		"an intent nobody implements": `{"intent":"upgrade"}`,
		"a timeout below the floor":   `{"timeout_seconds":1}`,
		"a timeout above the ceiling": `{"timeout_seconds":100000}`,
		"a misspelled field":          `{"intnet":"install"}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := protocol.ParseAppOptions([]byte(raw))
			if err == nil {
				t.Fatalf("%s should be refused", raw)
			}
			if !errors.Is(err, protocol.ErrBadOptions) {
				t.Errorf("error should wrap ErrBadOptions, got %v", err)
			}
		})
	}
}

// Uninstall is a deliberate instruction, not a consequence of leaving a group,
// so it is a first-class intent on the assignment.
func TestAppOptionsAcceptsUninstall(t *testing.T) {
	o, err := protocol.ParseAppOptions([]byte(`{"intent":"uninstall"}`))
	if err != nil {
		t.Fatal(err)
	}
	if o.Intent != protocol.IntentUninstall {
		t.Errorf("intent = %q, want uninstall", o.Intent)
	}
	raw, err := o.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"intent":"uninstall"`) {
		t.Errorf("the stored options should keep the intent, got %s", raw)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/protocol/ -run App -count=1`

Expected: FAIL to compile — `protocol.ParseAppOptions` is undefined.

- [ ] **Step 3: Write the implementation**

Create `internal/protocol/app.go`:

```go
package protocol

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"
)

// ItemKindApp is the assignment kind for application deployments.
const ItemKindApp = "app"

// What an assignment asks for. Removing software is a deliberate instruction,
// not a consequence of a device leaving a group.
const (
	IntentInstall   = "install"
	IntentUninstall = "uninstall"
)

// ScopeMachine installs for every user of the machine. It is the only scope:
// the agent runs as LocalSystem, so a per-user install would land in the
// system account's profile rather than any real person's.
const ScopeMachine = "machine"

// Limits on what an administrator may ask for. Installs are far slower than
// scripts, so the floor is higher and the ceiling is four hours.
const (
	MinAppTimeoutSeconds = 60
	MaxAppTimeoutSeconds = 14400
)

// AppOptions are the per-assignment settings of an app deployment. They travel
// to the agent on check-in, which is why they live here.
type AppOptions struct {
	Intent         string `json:"intent"`
	TimeoutSeconds int    `json:"timeout_seconds"`
}

// DefaultAppOptions are applied to anything the caller leaves out.
func DefaultAppOptions() AppOptions {
	return AppOptions{Intent: IntentInstall, TimeoutSeconds: 900}
}

// Timeout is the limit on one winget invocation.
func (o AppOptions) Timeout() time.Duration {
	return time.Duration(o.TimeoutSeconds) * time.Second
}

// ParseAppOptions validates raw assignment options, filling in the defaults.
// Unknown fields are rejected so a typo is not silently ignored.
func ParseAppOptions(raw []byte) (AppOptions, error) {
	o := DefaultAppOptions()
	if len(bytes.TrimSpace(raw)) > 0 && string(bytes.TrimSpace(raw)) != "null" {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&o); err != nil {
			return AppOptions{}, fmt.Errorf("%w: %v", ErrBadOptions, err)
		}
	}
	if err := o.validate(); err != nil {
		return AppOptions{}, err
	}
	return o, nil
}

func (o AppOptions) validate() error {
	switch o.Intent {
	case IntentInstall, IntentUninstall:
	default:
		return fmt.Errorf("%w: intent must be %q or %q, not %q",
			ErrBadOptions, IntentInstall, IntentUninstall, o.Intent)
	}
	if o.TimeoutSeconds < MinAppTimeoutSeconds || o.TimeoutSeconds > MaxAppTimeoutSeconds {
		return fmt.Errorf("%w: timeout_seconds must be between %d and %d",
			ErrBadOptions, MinAppTimeoutSeconds, MaxAppTimeoutSeconds)
	}
	return nil
}

// Marshal returns the canonical JSON for storing on an assignment.
func (o AppOptions) Marshal() ([]byte, error) { return json.Marshal(o) }

// AppVersionResponse is the body of
// GET /api/agent/v1/apps/{id}/versions/{version}.
type AppVersionResponse struct {
	Version int `json:"version"`
	// PackageID is the winget package, such as "7zip.7zip".
	PackageID string `json:"package_id"`
	// PinnedVersion is an exact version, or empty for whatever is current when
	// it is first installed.
	PinnedVersion string `json:"pinned_version"`
	Scope         string `json:"scope"`
	// InstallArgs are passed through to the installer, usually empty.
	InstallArgs string `json:"install_args"`
	Hash        string `json:"hash"`
}

// AppResult is POSTed to /api/agent/v1/apps/{id}/result to report one install
// or uninstall. Only terminal outcomes are reported.
type AppResult struct {
	Version int    `json:"version"`
	Intent  string `json:"intent"`
	Status  string `json:"status"`
	// InstalledVersion is what winget reports afterwards, so the console can
	// say which version a device actually has.
	InstalledVersion string `json:"installed_version"`
	ExitCode         int    `json:"exit_code"`
	Stdout           string `json:"stdout"`
	Stderr           string `json:"stderr"`
	StdoutTruncated  bool   `json:"stdout_truncated"`
	StderrTruncated  bool   `json:"stderr_truncated"`
	Error            string `json:"error"`
	// Detail is the short sentence the console shows, such as a note that a
	// restart is needed.
	Detail     string    `json:"detail"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/protocol/ -count=1 && go vet ./internal/protocol/`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/protocol/app.go internal/protocol/app_test.go
git commit -m "feat(protocol): the app item kind, its options and payloads"
```

---

### Task 5: Storage for apps

**Files:**
- Create: `internal/server/store/migrations/0008_apps.up.sql`
- Create: `internal/server/store/migrations/0008_apps.down.sql`
- Create: `internal/server/store/apps.go`
- Test: `internal/server/store/apps_test.go`

**Interfaces:**
- Consumes: `store.Page`, `store.DefaultTenantID`, `store.ErrNotFound`, `q.db` (a pgx pool or tx).
- Produces:
  ```go
  type App struct {
      ID uuid.UUID; Name, Description string; CurrentVersion int
      CreatedAt, UpdatedAt time.Time; CreatedBy string
  }
  type AppVersion struct {
      AppID uuid.UUID; Version int
      PackageID, PinnedVersion, Scope, InstallArgs, Hash string
      CreatedAt time.Time; CreatedBy string
  }
  type AppInstall struct {
      ID, AppID uuid.UUID; Version int; DeviceID uuid.UUID
      Hostname string // listing queries only
      Intent, Status, InstalledVersion string
      ExitCode int
      Stdout, Stderr string; StdoutTruncated, StderrTruncated bool
      Error, Detail string
      StartedAt, FinishedAt time.Time
  }

  func (q *Queries) CreateApp(ctx, a App) error
  func (q *Queries) GetApp(ctx, id uuid.UUID) (App, error)
  func (q *Queries) GetAppByName(ctx, name string) (App, error)
  func (q *Queries) ListApps(ctx, page Page) ([]App, int, error)
  func (q *Queries) UpdateApp(ctx, a App) error
  func (q *Queries) DeleteApp(ctx, id uuid.UUID) error
  func (q *Queries) CreateAppVersion(ctx, v AppVersion) error
  func (q *Queries) GetAppVersion(ctx, appID uuid.UUID, version int) (AppVersion, error)
  func (q *Queries) ListAppVersions(ctx, appID uuid.UUID) ([]AppVersion, error)
  func (q *Queries) InsertAppInstall(ctx, in AppInstall) error
  func (q *Queries) ListAppInstalls(ctx, appID uuid.UUID, deviceID *uuid.UUID, page Page) ([]AppInstall, int, error)
  ```

- [ ] **Step 1: Write the migration**

Create `internal/server/store/migrations/0008_apps.up.sql`:

```sql
CREATE TABLE apps (
    id              uuid PRIMARY KEY,
    tenant_id       uuid NOT NULL REFERENCES tenants(id),
    name            text NOT NULL,
    description     text NOT NULL DEFAULT '',
    current_version integer NOT NULL DEFAULT 0,
    created_at      timestamptz NOT NULL,
    updated_at      timestamptz NOT NULL,
    created_by      text NOT NULL
);
CREATE UNIQUE INDEX apps_name ON apps (tenant_id, lower(name));

-- Versions are immutable: an install is only meaningful if you know what was
-- asked for. Scope is constrained rather than free text because the agent runs
-- as LocalSystem, where a per-user install would land in the system account's
-- profile rather than any real person's.
CREATE TABLE app_versions (
    app_id         uuid NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    version        integer NOT NULL,
    tenant_id      uuid NOT NULL REFERENCES tenants(id),
    package_id     text NOT NULL,
    pinned_version text NOT NULL DEFAULT '',
    scope          text NOT NULL DEFAULT 'machine' CHECK (scope IN ('machine')),
    install_args   text NOT NULL DEFAULT '',
    hash           text NOT NULL,
    created_at     timestamptz NOT NULL,
    created_by     text NOT NULL,
    PRIMARY KEY (app_id, version)
);

-- app_id has no foreign key on purpose: installs outlive the app, because what
-- happened on a machine stays true after the app is deleted.
CREATE TABLE app_installs (
    id                uuid PRIMARY KEY,
    tenant_id         uuid NOT NULL REFERENCES tenants(id),
    app_id            uuid NOT NULL,
    version           integer NOT NULL,
    device_id         uuid NOT NULL REFERENCES devices(id),
    intent            text NOT NULL CHECK (intent IN ('install', 'uninstall')),
    status            text NOT NULL CHECK (status IN ('succeeded', 'failed')),
    -- What winget reports afterwards, so the console can say which version a
    -- device actually has rather than only which one was asked for.
    installed_version text NOT NULL DEFAULT '',
    exit_code         integer NOT NULL,
    stdout            text NOT NULL DEFAULT '',
    stderr            text NOT NULL DEFAULT '',
    stdout_truncated  boolean NOT NULL DEFAULT false,
    stderr_truncated  boolean NOT NULL DEFAULT false,
    error             text NOT NULL DEFAULT '',
    detail            text NOT NULL DEFAULT '',
    started_at        timestamptz NOT NULL,
    finished_at       timestamptz NOT NULL
);
CREATE INDEX app_installs_recent ON app_installs (app_id, device_id, started_at DESC);
```

Create `internal/server/store/migrations/0008_apps.down.sql`:

```sql
DROP TABLE app_installs;
DROP TABLE app_versions;
DROP TABLE apps;
```

**Do not** add `assignments.options` or `device_item_status.version` — migration `0005_scripts.up.sql` already added both, and apps report only statuses the existing `device_item_status` CHECK constraint allows.

- [ ] **Step 2: Write the failing test**

Create `internal/server/store/apps_test.go`, following whatever the existing `scripts_test.go` in that package does to get a `*store.Store` (it is `storetest.New(t)`):

```go
package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"retune/internal/server/store"
	"retune/internal/server/store/storetest"
)

func TestAppRoundTrip(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	q := st.Q()
	now := time.Now().UTC().Truncate(time.Millisecond)

	a := store.App{
		ID: uuid.Must(uuid.NewV7()), Name: "7-Zip", Description: "archiver",
		CurrentVersion: 1, CreatedAt: now, UpdatedAt: now, CreatedBy: "ops",
	}
	if err := q.CreateApp(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := q.CreateAppVersion(ctx, store.AppVersion{
		AppID: a.ID, Version: 1, PackageID: "7zip.7zip", Scope: "machine",
		Hash: "abc", CreatedAt: now, CreatedBy: "ops",
	}); err != nil {
		t.Fatal(err)
	}

	got, err := q.GetApp(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "7-Zip" || got.CurrentVersion != 1 {
		t.Fatalf("app = %+v", got)
	}

	v, err := q.GetAppVersion(ctx, a.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if v.PackageID != "7zip.7zip" || v.Scope != "machine" {
		t.Fatalf("version = %+v", v)
	}

	// A name is unique per tenant, case-insensitively, so two people cannot
	// each create "7-zip" and wonder which one is assigned.
	dup := a
	dup.ID, dup.Name = uuid.Must(uuid.NewV7()), "7-zip"
	if err := q.CreateApp(ctx, dup); err == nil {
		t.Error("a duplicate name should be refused")
	}

	if _, err := q.GetApp(ctx, uuid.Must(uuid.NewV7())); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("a missing app should be ErrNotFound, got %v", err)
	}
}

// Installs outlive the app they describe: what happened on a machine stays
// true after somebody deletes the deployment.
func TestAppInstallsSurviveDeletion(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	q := st.Q()
	now := time.Now().UTC().Truncate(time.Millisecond)

	device := storetest.Device(t, st, "DESKTOP-APPS")
	a := store.App{
		ID: uuid.Must(uuid.NewV7()), Name: "Doomed", CurrentVersion: 1,
		CreatedAt: now, UpdatedAt: now, CreatedBy: "ops",
	}
	if err := q.CreateApp(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := q.InsertAppInstall(ctx, store.AppInstall{
		ID: uuid.Must(uuid.NewV7()), AppID: a.ID, Version: 1, DeviceID: device,
		Intent: "install", Status: "succeeded", InstalledVersion: "26.03",
		StartedAt: now, FinishedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := q.DeleteApp(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	rows, total, err := q.ListAppInstalls(ctx, a.ID, nil, store.Page{})
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(rows) != 1 || rows[0].InstalledVersion != "26.03" {
		t.Fatalf("the install should have survived, got %d rows %+v", total, rows)
	}
}
```

If `storetest` has no `Device` helper, read `internal/server/store/storetest/` and insert a device however the existing tests in that package do; do not invent an API.

- [ ] **Step 3: Run the test to verify it fails**

Run: `go test ./internal/server/store/ -run App -count=1`

Expected: FAIL to compile — `store.App` and its queries do not exist.

- [ ] **Step 4: Write the queries**

Create `internal/server/store/apps.go`, following `internal/server/store/scripts.go` exactly: a `const appCols`, a `scanApp(row pgx.Row)` helper, `count(*) OVER () AS total` for the paginated lists, `DefaultTenantID` in every WHERE and INSERT, and `ErrNotFound` mapped from `pgx.ErrNoRows`. For example:

```go
const appCols = `id, name, description, current_version, created_at, updated_at, created_by`

// CreateApp adds an app to the library.
func (q *Queries) CreateApp(ctx context.Context, a App) error {
	_, err := q.db.Exec(ctx, `
		INSERT INTO apps (id, tenant_id, name, description, current_version, created_at, updated_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $6, $7)`,
		a.ID, DefaultTenantID, a.Name, a.Description, a.CurrentVersion, a.CreatedAt, a.CreatedBy)
	return err
}
```

`ListAppInstalls` joins `devices` to fill `Hostname`, and orders `started_at DESC, id DESC` — the same tie-break `ListScriptRuns` uses, because two installs can share a timestamp and UUIDv7 sorts by creation time.

- [ ] **Step 5: Run the tests**

Run: `go test ./internal/server/store/ -count=1`

Expected: PASS. The migration runs automatically against the throwaway Postgres.

- [ ] **Step 6: Commit**

```bash
git add internal/server/store/migrations/0008_apps.up.sql internal/server/store/migrations/0008_apps.down.sql internal/server/store/apps.go internal/server/store/apps_test.go
git commit -m "feat(store): apps, their versions and their install history"
```

---

### Task 6: The apps service

**Files:**
- Create: `internal/server/apps/service.go`
- Test: `internal/server/apps/service_test.go`

**Interfaces:**
- Consumes: everything Task 5 produced, plus `protocol.ItemKindApp`, `protocol.AppResult`, `protocol.IntentInstall`, `protocol.IntentUninstall`, `protocol.ResultSucceeded`, `protocol.ScopeMachine`, `protocol.MaxOutputBytes`, `store.InTx`, `store.AuditEntry`, `store.SetItemStatus`.
- Produces:
  ```go
  var ErrNotFound, ErrNameTaken, ErrBadRequest error
  type Service struct { Store *store.Store; Now func() time.Time }
  type NewApp struct { Name, Description, PackageID, PinnedVersion, Scope, InstallArgs, Actor string }
  func Hash(packageID, pinned, scope, args string) string
  func (s *Service) Create(ctx, in NewApp) (store.App, error)
  func (s *Service) Update(ctx, id uuid.UUID, in NewApp) (store.App, error)
  func (s *Service) Delete(ctx, id uuid.UUID, actor string) error
  func (s *Service) Get(ctx, id uuid.UUID) (store.App, error)
  func (s *Service) List(ctx, page store.Page) ([]store.App, int, error)
  func (s *Service) Version(ctx, id uuid.UUID, version int) (store.AppVersion, error)
  func (s *Service) ListVersions(ctx, id uuid.UUID) ([]store.AppVersion, error)
  func (s *Service) RecordInstall(ctx, deviceID, appID uuid.UUID, r protocol.AppResult) error
  ```

- [ ] **Step 1: Write the failing test**

Create `internal/server/apps/service_test.go`:

```go
package apps_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"retune/internal/protocol"
	"retune/internal/server/apps"
	"retune/internal/server/store"
	"retune/internal/server/store/storetest"
)

func service(st *store.Store) *apps.Service { return &apps.Service{Store: st} }

// Renaming an app does not make every device install it again; changing what
// gets installed does.
func TestUpdateBumpsTheVersionOnlyWhenTheDefinitionChanges(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := service(st)

	a, err := svc.Create(ctx, apps.NewApp{Name: "7-Zip", PackageID: "7zip.7zip", Actor: "ops"})
	if err != nil {
		t.Fatal(err)
	}
	if a.CurrentVersion != 1 {
		t.Fatalf("a new app starts at version 1, got %d", a.CurrentVersion)
	}

	renamed, err := svc.Update(ctx, a.ID, apps.NewApp{
		Name: "7-Zip archiver", Description: "handy", PackageID: "7zip.7zip", Actor: "ops",
	})
	if err != nil {
		t.Fatal(err)
	}
	if renamed.CurrentVersion != 1 {
		t.Errorf("renaming should not redeploy, got version %d", renamed.CurrentVersion)
	}

	pinned, err := svc.Update(ctx, a.ID, apps.NewApp{
		Name: "7-Zip archiver", PackageID: "7zip.7zip", PinnedVersion: "26.03", Actor: "ops",
	})
	if err != nil {
		t.Fatal(err)
	}
	if pinned.CurrentVersion != 2 {
		t.Errorf("pinning a version is a new definition, got version %d", pinned.CurrentVersion)
	}
	v, err := svc.Version(ctx, a.ID, 2)
	if err != nil {
		t.Fatal(err)
	}
	if v.PinnedVersion != "26.03" {
		t.Errorf("version 2 should carry the pin, got %+v", v)
	}
}

func TestCreateRejectsBadInput(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := service(st)

	cases := map[string]apps.NewApp{
		"no name":       {PackageID: "7zip.7zip", Actor: "ops"},
		"no package":    {Name: "Nameless", Actor: "ops"},
		"a user scope":  {Name: "Per user", PackageID: "7zip.7zip", Scope: "user", Actor: "ops"},
		"a made-up scope": {Name: "Odd", PackageID: "7zip.7zip", Scope: "galaxy", Actor: "ops"},
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := svc.Create(ctx, in); !errors.Is(err, apps.ErrBadRequest) {
				t.Fatalf("want ErrBadRequest, got %v", err)
			}
		})
	}
}

// The reported install and the device's status are written together, so the
// console's summary can never disagree with the history behind it.
func TestRecordInstallWritesHistoryAndStatus(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := service(st)
	device := storetest.Device(t, st, "DESKTOP-APPS")

	a, err := svc.Create(ctx, apps.NewApp{Name: "7-Zip", PackageID: "7zip.7zip", Actor: "ops"})
	if err != nil {
		t.Fatal(err)
	}
	err = svc.RecordInstall(ctx, device, a.ID, protocol.AppResult{
		Version: 1, Intent: protocol.IntentInstall, Status: protocol.ResultSucceeded,
		InstalledVersion: "26.03",
	})
	if err != nil {
		t.Fatal(err)
	}

	rollup, err := st.Q().ItemStatusRollup(ctx, protocol.ItemKindApp, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if rollup[store.ItemSucceeded] != 1 {
		t.Fatalf("want one succeeded, got %v", rollup)
	}
	rows, _, err := st.Q().ListAppInstalls(ctx, a.ID, nil, store.Page{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].InstalledVersion != "26.03" {
		t.Fatalf("the install should be in the history, got %+v", rows)
	}
}

// Deleting an app takes its assignments with it, or a device would keep being
// told to install something that no longer exists.
func TestDeleteRemovesAssignments(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := service(st)

	a, err := svc.Create(ctx, apps.NewApp{Name: "Doomed", PackageID: "x.y", Actor: "ops"})
	if err != nil {
		t.Fatal(err)
	}
	err = st.Q().CreateAssignment(ctx, store.Assignment{
		ID: uuid.Must(uuid.NewV7()), ItemKind: protocol.ItemKindApp, ItemID: a.ID,
		GroupID: uuid.MustParse("00000000-0000-0000-0000-000000000002"),
		Mode:    store.ModeInclude, CreatedBy: "ops",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Delete(ctx, a.ID, "ops"); err != nil {
		t.Fatal(err)
	}
	rows, err := st.Q().ListAssignments(ctx, protocol.ItemKindApp, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("assignments should have gone too, got %+v", rows)
	}
}
```

`store.Assignment` may need a `CreatedAt`; fill it from `time.Now()` if the insert complains.

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/server/apps/ -count=1`

Expected: FAIL to compile — the package does not exist.

- [ ] **Step 3: Write the service**

Create `internal/server/apps/service.go` modelled line for line on `internal/server/scripts/service.go`. Points that differ:

```go
// Hash identifies a version's definition. Name and description are not part of
// it: renaming an app is not a reason to install it again.
func Hash(packageID, pinned, scope, args string) string {
	sum := sha256.Sum256([]byte(packageID + "\x00" + pinned + "\x00" + scope + "\x00" + args))
	return hex.EncodeToString(sum[:])
}

func (in NewApp) validate() error {
	if strings.TrimSpace(in.Name) == "" {
		return fmt.Errorf("%w: an app needs a name", ErrBadRequest)
	}
	if strings.TrimSpace(in.PackageID) == "" {
		return fmt.Errorf("%w: an app needs a winget package id", ErrBadRequest)
	}
	// Machine scope is the only one. The agent runs as the system account, so
	// a per-user install would land in its profile rather than a person's.
	if in.Scope != "" && in.Scope != protocol.ScopeMachine {
		return fmt.Errorf("%w: scope must be %q", ErrBadRequest, protocol.ScopeMachine)
	}
	return nil
}
```

`Create` defaults an empty `Scope` to `protocol.ScopeMachine` before storing. `Update` compares `Hash(...)` of the incoming definition against the current version's stored `Hash` and only then bumps `CurrentVersion` and writes a new `app_versions` row. Audit actions are `app.created`, `app.updated`, `app.deleted` with `TargetKind: "app"`.

`RecordInstall` mirrors `scripts.RecordRun`:

```go
// RecordInstall stores one reported install or uninstall and updates the
// device's status for that app, both in one transaction so the summary can
// never disagree with the history.
func (s *Service) RecordInstall(ctx context.Context, deviceID, appID uuid.UUID, r protocol.AppResult) error {
	switch r.Status {
	case protocol.ResultSucceeded, protocol.ResultFailed:
	default:
		return fmt.Errorf("%w: unsupported install status %q", ErrBadRequest, r.Status)
	}
	switch r.Intent {
	case protocol.IntentInstall, protocol.IntentUninstall:
	default:
		return fmt.Errorf("%w: unsupported intent %q", ErrBadRequest, r.Intent)
	}

	now := s.now()
	stdout, stdoutTruncated := clamp(r.Stdout, r.StdoutTruncated)
	stderr, stderrTruncated := clamp(r.Stderr, r.StderrTruncated)
	errText, _ := clamp(r.Error, false)
	detail, _ := clamp(r.Detail, false)

	status := store.ItemSucceeded
	if r.Status != protocol.ResultSucceeded {
		status = store.ItemFailed
	}
	if detail == "" {
		switch {
		case errText != "":
			detail = errText
		case r.Status != protocol.ResultSucceeded:
			detail = fmt.Sprintf("winget exited %d", r.ExitCode)
		case r.Intent == protocol.IntentUninstall:
			detail = "removed"
		case r.InstalledVersion != "":
			detail = "installed " + r.InstalledVersion
		}
	}

	return s.Store.InTx(ctx, func(q *store.Queries) error {
		if err := q.InsertAppInstall(ctx, store.AppInstall{
			ID: uuid.Must(uuid.NewV7()), AppID: appID, Version: r.Version, DeviceID: deviceID,
			Intent: r.Intent, Status: r.Status, InstalledVersion: r.InstalledVersion,
			ExitCode: r.ExitCode, Stdout: stdout, Stderr: stderr,
			StdoutTruncated: stdoutTruncated, StderrTruncated: stderrTruncated,
			Error: errText, Detail: detail, StartedAt: r.StartedAt, FinishedAt: r.FinishedAt,
		}); err != nil {
			return err
		}
		return q.SetItemStatus(ctx, store.ItemStatus{
			DeviceID: deviceID, ItemKind: protocol.ItemKindApp, ItemID: appID,
			Status: status, Detail: detail, Version: r.Version, UpdatedAt: now,
		})
	})
}
```

Copy `clamp` from `internal/server/scripts/service.go` verbatim into this package — it is unexported there, and the replacement argument to `strings.ToValidUTF8` is the literal U+FFFD character.

Do **not** add a `SetItemPending` here. Scripts need one because the server
knows, from the check-in, that a run-as-user deployment cannot run yet. Nothing
equivalent is true of an app: the server cannot tell from a check-in whether
winget will work, so every app status comes from a result the agent reported.

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/server/apps/ -count=1 && go vet ./internal/server/apps/`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/server/apps/
git commit -m "feat(server): the apps service, with immutable versions"
```

---

### Task 7: The admin API for apps

**Files:**
- Create: `internal/server/adminapi/apps.go`
- Modify: `internal/server/adminapi/resources.go` — mount the routes
- Modify: `internal/server/adminapi/handler.go` — add the `Apps *apps.Service` field
- Modify: `internal/server/adminapi/itemkinds.go` — register the app options parser
- Modify: `internal/server/app/app.go` — construct and inject the service
- Test: `internal/server/app/apps_test.go`

**Interfaces:**
- Consumes: Task 6's `apps.Service`, Task 4's `protocol.ParseAppOptions`, Task 1's `optionsParsers`.
- Produces: the seven `/apps` routes, and `App.Apps` on the `app.App` struct so tests can reach the service.

- [ ] **Step 1: Write the failing test**

Create `internal/server/app/apps_test.go`:

```go
package app_test

import (
	"net/http"
	"strings"
	"testing"

	"retune/internal/server/store"
)

type appResp struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	PackageID      string `json:"package_id"`
	PinnedVersion  string `json:"pinned_version"`
	Scope          string `json:"scope"`
	CurrentVersion int    `json:"current_version"`
}

func TestAppLifecycle(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)

	status, body := admin.do(http.MethodPost, "/apps", map[string]any{
		"name": "7-Zip", "description": "archiver", "package_id": "7zip.7zip",
	})
	if status != http.StatusCreated {
		t.Fatalf("create: %d %s", status, body)
	}
	app := decodeJSON[appResp](t, body)
	if app.Scope != "machine" || app.CurrentVersion != 1 {
		t.Fatalf("a new app should default to machine scope at version 1, got %+v", app)
	}

	status, body = admin.do(http.MethodGet, "/apps/"+app.ID, nil)
	if status != http.StatusOK {
		t.Fatalf("get: %d %s", status, body)
	}
	if got := decodeJSON[appResp](t, body); got.PackageID != "7zip.7zip" {
		t.Errorf("the editor needs the package id, got %+v", got)
	}

	status, body = admin.do(http.MethodDelete, "/apps/"+app.ID, nil)
	if status != http.StatusNoContent {
		t.Fatalf("delete: %d %s", status, body)
	}
}

// An app assignment carries an intent, and it is validated at the API rather
// than left for the agent to puzzle over.
func TestAppAssignmentIntent(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)

	_, body := admin.do(http.MethodPost, "/apps", map[string]any{
		"name": "7-Zip", "package_id": "7zip.7zip",
	})
	app := decodeJSON[appResp](t, body)

	status, body := admin.do(http.MethodPost, "/assignments", map[string]any{
		"item_kind": "app", "item_id": app.ID,
		"group_id": "00000000-0000-0000-0000-000000000002", "mode": "include",
		"options": map[string]any{"intent": "uninstall"},
	})
	if status != http.StatusCreated {
		t.Fatalf("assign: %d %s", status, body)
	}
	if !strings.Contains(string(body), `"intent":"uninstall"`) {
		t.Errorf("the stored options should keep the intent, got %s", body)
	}

	status, body = admin.do(http.MethodPost, "/assignments", map[string]any{
		"item_kind": "app", "item_id": app.ID,
		"group_id": "00000000-0000-0000-0000-000000000002", "mode": "include",
		"options": map[string]any{"intent": "upgrade"},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("an intent nobody implements should be refused, got %d %s", status, body)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/server/app/ -run App -count=1`

Expected: FAIL — `POST /apps` is 404, because the route does not exist.

- [ ] **Step 3: Write the handlers**

Create `internal/server/adminapi/apps.go` modelled on `internal/server/adminapi/scripts.go`: an `appJSON` struct and `newAppJSON`, an `appRequest`, a `writeAppError` mapping `apps.ErrNotFound`/`ErrNameTaken`/`ErrBadRequest`, and `listApps`, `createApp`, `getApp`, `updateApp`, `deleteApp`, `listAppVersions`, `listAppInstalls`.

`getApp` fills the definition from the current version the way `getScript` fills the body:

```go
	out := newAppJSON(app)
	if v, err := h.Apps.Version(ctx, id, app.CurrentVersion); err == nil {
		out.PackageID, out.PinnedVersion = v.PackageID, v.PinnedVersion
		out.Scope, out.InstallArgs = v.Scope, v.InstallArgs
	}
	writeJSON(w, http.StatusOK, out)
```

The listing includes `package_id` too, since it identifies an app at a glance in a way its name may not.

- [ ] **Step 4: Register the routes, the parser and the service**

In `internal/server/adminapi/resources.go`, beside the `/profiles` block:

```go
	mux.Handle("GET "+base+"/apps", h.read(h.listApps))
	mux.Handle("POST "+base+"/apps", h.write(h.createApp))
	mux.Handle("GET "+base+"/apps/{id}", h.read(h.getApp))
	mux.Handle("POST "+base+"/apps/{id}", h.write(h.updateApp))
	mux.Handle("DELETE "+base+"/apps/{id}", h.write(h.deleteApp))
	mux.Handle("GET "+base+"/apps/{id}/versions", h.read(h.listAppVersions))
	mux.Handle("GET "+base+"/apps/{id}/installs", h.read(h.listAppInstalls))
```

In `internal/server/adminapi/itemkinds.go`, add to `optionsParsers`:

```go
	protocol.ItemKindApp: func(raw json.RawMessage) ([]byte, error) {
		opts, err := protocol.ParseAppOptions(raw)
		if err != nil {
			return nil, err
		}
		return opts.Marshal()
	},
```

Add `Apps *apps.Service` to the `adminapi.Handler` struct. In `internal/server/app/app.go`, add `Apps *apps.Service` to the `App` struct, construct `appSvc := &apps.Service{Store: st, Now: time.Now}` beside `prof`, pass `Apps: appSvc` to both the `adminapi.Handler` and the `agentapi.Handler` literals, and add `Apps: appSvc` to the returned `&App{...}`.

- [ ] **Step 5: Run the tests**

Run: `go test ./internal/server/... -count=1`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/server/adminapi/apps.go internal/server/adminapi/resources.go internal/server/adminapi/handler.go internal/server/adminapi/itemkinds.go internal/server/app/app.go internal/server/app/apps_test.go
git commit -m "feat(api): manage apps from the admin API"
```

---

### Task 8: The agent API for apps

**Files:**
- Modify: `internal/server/agentapi/handler.go` — the `Apps` field, two routes, two handlers, the `itemVersion` case
- Test: `internal/server/app/apps_test.go`

**Interfaces:**
- Consumes: Task 2's `itemVersion`, Task 6's `apps.Service`, Task 4's `protocol.AppVersionResponse` and `protocol.AppResult`.
- Produces: `GET /api/agent/v1/apps/{id}/versions/{version}` and `POST /api/agent/v1/apps/{id}/result`.

- [ ] **Step 1: Write the failing test**

Add to `internal/server/app/apps_test.go`:

```go
// A device may only read what it has been given, and an app it was never
// assigned is a 404 -- the same answer as one that does not exist, which is
// all an agent needs to know.
func TestAgentReadsOnlyAssignedApps(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)
	_, agent := enrollDevice(t, a, srv, "DESKTOP-APPS")

	_, body := admin.do(http.MethodPost, "/apps", map[string]any{
		"name": "7-Zip", "package_id": "7zip.7zip",
	})
	app := decodeJSON[appResp](t, body)

	status, _ := send(t, agent, http.MethodGet,
		srv.URL+"/api/agent/v1/apps/"+app.ID+"/versions/1", nil)
	if status != http.StatusNotFound {
		t.Fatalf("an unassigned app must not be readable, got %d", status)
	}

	status, body = admin.do(http.MethodPost, "/assignments", map[string]any{
		"item_kind": "app", "item_id": app.ID,
		"group_id": "00000000-0000-0000-0000-000000000002", "mode": "include",
	})
	if status != http.StatusCreated {
		t.Fatalf("assign: %d %s", status, body)
	}

	status, body = send(t, agent, http.MethodGet,
		srv.URL+"/api/agent/v1/apps/"+app.ID+"/versions/1", nil)
	if status != http.StatusOK {
		t.Fatalf("version: %d %s", status, body)
	}
	if got := decodeJSON[protocol.AppVersionResponse](t, body); got.PackageID != "7zip.7zip" {
		t.Errorf("version = %+v", got)
	}
}

// Check-in offers the app with its current version, and a reported result
// settles the device's status.
func TestAppReachesTheAgentAndReportsBack(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)
	_, agent := enrollDevice(t, a, srv, "DESKTOP-APPS")

	_, body := admin.do(http.MethodPost, "/apps", map[string]any{
		"name": "7-Zip", "package_id": "7zip.7zip",
	})
	app := decodeJSON[appResp](t, body)
	admin.do(http.MethodPost, "/assignments", map[string]any{
		"item_kind": "app", "item_id": app.ID,
		"group_id": "00000000-0000-0000-0000-000000000002", "mode": "include",
	})

	status, body := send(t, agent, http.MethodPost, srv.URL+"/api/agent/v1/checkin",
		protocol.CheckinRequest{AgentVersion: "1.0.0"})
	if status != http.StatusOK {
		t.Fatalf("checkin: %d %s", status, body)
	}
	items := decodeJSON[protocol.CheckinResponse](t, body).Items
	if len(items) != 1 || items[0].Kind != protocol.ItemKindApp || items[0].Version != 1 {
		t.Fatalf("the app should be offered at version 1, got %+v", items)
	}

	status, body = send(t, agent, http.MethodPost,
		srv.URL+"/api/agent/v1/apps/"+app.ID+"/result",
		protocol.AppResult{
			Version: 1, Intent: protocol.IntentInstall, Status: protocol.ResultSucceeded,
			InstalledVersion: "26.03",
		})
	if status != http.StatusNoContent {
		t.Fatalf("report: %d %s", status, body)
	}

	status, body = admin.do(http.MethodGet, "/items/app/"+app.ID+"/status", nil)
	if status != http.StatusOK {
		t.Fatalf("status: %d %s", status, body)
	}
	resp := decodeJSON[itemStatusResp](t, body)
	if resp.Rollup[store.ItemSucceeded] != 1 {
		t.Fatalf("want one succeeded, got %v", resp.Rollup)
	}
	if !strings.Contains(resp.Items[0].Detail, "26.03") {
		t.Errorf("the detail should say which version landed, got %q", resp.Items[0].Detail)
	}
}
```

`itemStatusResp` already exists in `internal/server/app/scripts_test.go` in the same package; reuse it rather than declaring a second one.

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/server/app/ -run 'AgentReadsOnlyAssignedApps|AppReachesTheAgent' -count=1`

Expected: FAIL — the agent routes 404.

- [ ] **Step 3: Add the field, the routes and the `itemVersion` case**

Add `Apps *apps.Service` to the `agentapi.Handler` struct. In `Routes()`, beside the profile pair:

```go
	mux.Handle("GET /api/agent/v1/apps/{id}/versions/{version}", h.requireDevice(h.appVersion))
	mux.Handle("POST /api/agent/v1/apps/{id}/result", h.requireDevice(h.appResult))
```

In `itemVersion` from Task 2, add:

```go
	case protocol.ItemKindApp:
		app, err := h.Apps.Get(ctx, it.ID)
		if err != nil {
			h.Log.Warn("assigned app is missing", "app_id", it.ID, "error", err)
			return 0, false
		}
		return app.CurrentVersion, true
```

- [ ] **Step 4: Write the two handlers**

Model `appVersion` on `scriptVersion` exactly — parse the id and version, `DeviceHasItem(ctx, a.Device.ID, protocol.ItemKindApp, id)`, then `h.Apps.Version`, answering 404 as `app_not_found` in every failing case:

```go
	writeJSON(w, http.StatusOK, protocol.AppVersionResponse{
		Version: v.Version, PackageID: v.PackageID, PinnedVersion: v.PinnedVersion,
		Scope: v.Scope, InstallArgs: v.InstallArgs, Hash: v.Hash,
	})
```

Model `appResult` on `scriptRun` exactly, decoding into `protocol.AppResult`, calling `h.Apps.RecordInstall`, and mapping `apps.ErrBadRequest` to 400 and everything else to 500.

- [ ] **Step 5: Run the tests**

Run: `go test ./internal/server/... ./test/e2e/ -count=1`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/server/agentapi/handler.go internal/server/app/apps_test.go
git commit -m "feat(api): serve app definitions to agents and take their results"
```

---

### Task 9: Driving winget

**Files:**
- Create: `internal/agent/apps/winget.go`
- Create: `internal/agent/apps/winget_test.go`

**Interfaces:**
- Produces:
  ```go
  const NotInstalledExit = -1978335212
  const RebootRequiredExit = 3010

  type Outcome int
  const (OutcomeSucceeded Outcome = iota; OutcomeNotInstalled; OutcomeRebootRequired; OutcomeFailed)
  func classify(code int) Outcome

  type Result struct {
      ExitCode int
      Stdout, Stderr string
      OutCut, ErrCut bool
      Err error
      TimedOut bool
  }

  // Winget runs winget commands. The agent uses one; tests supply a fake.
  type Winget interface {
      Detect(ctx context.Context, packageID string) (installed bool, version string, r Result)
      Install(ctx context.Context, v protocol.AppVersionResponse) Result
      Uninstall(ctx context.Context, packageID string) Result
  }

  func New() (Winget, error)   // resolves winget.exe; ErrNoAppInstaller when absent
  var ErrNoAppInstaller = errors.New("this machine has no App Installer, so winget cannot run")

  func detectArgs(packageID string) []string
  func installArgs(v protocol.AppVersionResponse) []string
  func uninstallArgs(packageID string) []string
  func installedVersion(stdout, packageID string) string
  ```

- [ ] **Step 1: Write the failing test**

Create `internal/agent/apps/winget_test.go`:

```go
package apps

import (
	"slices"
	"strings"
	"testing"

	"retune/internal/protocol"
)

// The msstore source prompts for an agreement and sends the machine's region
// upstream, so every invocation pins the winget source.
func TestEveryCommandPinsTheSource(t *testing.T) {
	cases := map[string][]string{
		"detect":    detectArgs("7zip.7zip"),
		"install":   installArgs(protocol.AppVersionResponse{PackageID: "7zip.7zip", Scope: "machine"}),
		"uninstall": uninstallArgs("7zip.7zip"),
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			if !slices.Contains(args, "--source") || !slices.Contains(args, "winget") {
				t.Errorf("%v should pin --source winget", args)
			}
			if !slices.Contains(args, "--exact") {
				t.Errorf("%v should match the id exactly, or a search could install the wrong thing", args)
			}
			if !slices.Contains(args, "--disable-interactivity") {
				t.Errorf("%v runs unattended and must never wait for a person", args)
			}
		})
	}
}

// An install is silent, machine-wide, and pins the version when one is asked
// for. Extra arguments the author supplied come last, so they reach the
// installer rather than winget.
func TestInstallArgs(t *testing.T) {
	args := installArgs(protocol.AppVersionResponse{
		PackageID: "7zip.7zip", PinnedVersion: "26.03", Scope: "machine",
		InstallArgs: "/NORESTART",
	})
	joined := strings.Join(args, " ")
	for _, want := range []string{
		"install", "--id 7zip.7zip", "--version 26.03", "--scope machine",
		"--silent", "--accept-package-agreements",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("%q should contain %q", joined, want)
		}
	}
	if args[len(args)-1] != "/NORESTART" {
		t.Errorf("author arguments belong last, got %v", args)
	}

	// With nothing pinned, no --version is passed at all: winget then
	// installs whatever is current, which is what an unpinned app means.
	plain := installArgs(protocol.AppVersionResponse{PackageID: "7zip.7zip", Scope: "machine"})
	if slices.Contains(plain, "--version") {
		t.Errorf("an unpinned app should not pin a version, got %v", plain)
	}
}

// "Not installed" is a specific exit code, not empty output. Treating it as a
// failure would make every first install look broken.
func TestClassify(t *testing.T) {
	cases := map[int]Outcome{
		0:                  OutcomeSucceeded,
		NotInstalledExit:   OutcomeNotInstalled,
		RebootRequiredExit: OutcomeRebootRequired,
		1:                  OutcomeFailed,
		-1:                 OutcomeFailed,
	}
	for code, want := range cases {
		if got := classify(code); got != want {
			t.Errorf("classify(%d) = %v, want %v", code, got, want)
		}
	}
}

// winget prints a table; the installed version is the column after the id.
func TestInstalledVersion(t *testing.T) {
	const out = `
Name                 Id          Version
-----------------------------------------
7-Zip                7zip.7zip   26.03
`
	if got := installedVersion(out, "7zip.7zip"); got != "26.03" {
		t.Errorf("installedVersion = %q, want 26.03", got)
	}
	if got := installedVersion("No installed package found matching input criteria.", "7zip.7zip"); got != "" {
		t.Errorf("nothing installed means no version, got %q", got)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/agent/apps/ -count=1`

Expected: FAIL to compile — the package does not exist.

- [ ] **Step 3: Write the implementation**

Create `internal/agent/apps/winget.go`. It is **not** behind a build tag: the argument building and classification are portable and unit-tested everywhere. Only `New()` and the process execution need Windows, so put those in `winget_windows.go` and a `winget_other.go` stub returning `ErrNoAppInstaller`, following the `winsession` package's split.

```go
// Package apps installs and removes the applications assigned to this device,
// by driving winget.
package apps

// Exit codes worth naming. Zero and NotInstalledExit were observed on a real
// machine; the reboot code is Windows Installer's standard one. Anything not
// named here is a plain failure, which is the safe default: a machine wrongly
// reported failed gets looked at, one wrongly reported succeeded does not.
const (
	// NotInstalledExit is APPINSTALLER_CLI_ERROR_NO_APPLICATIONS_FOUND. It is
	// how `winget list` says the package is absent, and is the detection
	// signal rather than an error.
	NotInstalledExit = -1978335212
	// RebootRequiredExit means the install worked and Windows wants a restart.
	RebootRequiredExit = 3010
)

// baseArgs are on every invocation. --source winget keeps the Store out of it:
// msstore prompts for an agreement and needs the machine's region sent
// upstream, and cannot be installed from silently.
func baseArgs() []string {
	return []string{"--exact", "--source", "winget",
		"--disable-interactivity", "--accept-source-agreements"}
}

func detectArgs(packageID string) []string {
	return append([]string{"list", "--id", packageID}, baseArgs()...)
}

func installArgs(v protocol.AppVersionResponse) []string {
	args := append([]string{"install", "--id", v.PackageID}, baseArgs()...)
	if strings.TrimSpace(v.PinnedVersion) != "" {
		args = append(args, "--version", v.PinnedVersion)
	}
	args = append(args, "--scope", v.Scope, "--silent", "--accept-package-agreements")
	// Anything the author added goes last, so it reaches the installer rather
	// than being read as a winget flag.
	if extra := strings.Fields(v.InstallArgs); len(extra) > 0 {
		args = append(args, extra...)
	}
	return args
}

func uninstallArgs(packageID string) []string {
	return append([]string{"uninstall", "--id", packageID, "--silent"}, baseArgs()...)
}
```

`installedVersion` scans the output for the line containing the package ID and returns the next whitespace-separated field after it, returning `""` when there is none.

In `winget_windows.go`, `New()` lists `%ProgramFiles%\WindowsApps` for directories matching `Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe`, sorts descending by name, and returns the one containing `winget.exe`; with none, `ErrNoAppInstaller`. Running a command uses `exec.CommandContext`, captures stdout and stderr into `executor.NewCapped(protocol.MaxOutputBytes)`, and **decodes the bytes as UTF-8 explicitly** — winget writes UTF-8 and the default console decoding mangles it.

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/agent/apps/ -count=1 && go vet ./... && GOOS=linux go build ./...`

Expected: PASS on both platforms.

- [ ] **Step 5: Commit**

```bash
git add internal/agent/apps/
git commit -m "feat(agent): drive winget, and name the exit codes that matter"
```

---

### Task 10: Deciding what to do

**Files:**
- Create: `internal/agent/apps/scheduler.go`
- Create: `internal/agent/apps/scheduler_test.go`
- Modify: `internal/agent/state/state.go` — `bucketApps`, `AppState`, accessors

**Interfaces:**
- Produces:
  ```go
  // state package
  type AppState struct {
      Version     int       `json:"version"`
      Intent      string    `json:"intent"`
      LastActedAt time.Time `json:"last_acted_at"`
      LastStatus  string    `json:"last_status"`
      LastSeenAt  time.Time `json:"last_seen_at"`   // last successful detection
      Installed   bool      `json:"installed"`
      Failures    int       `json:"failures"`
  }
  func (s *Store) AppState(id string) (AppState, error)
  func (s *Store) SetAppState(id string, st AppState) error

  // apps package
  const DetectEvery = time.Hour
  type Action int
  const (ActionNone Action = iota; ActionDetect; ActionInstall; ActionUninstall)
  type Decision struct { Action Action; Reason string }
  func Decide(version int, opts protocol.AppOptions, st state.AppState, now time.Time) Decision
  ```

- [ ] **Step 1: Write the failing test**

Create `internal/agent/apps/scheduler_test.go`:

```go
package apps_test

import (
	"testing"
	"time"

	"retune/internal/agent/apps"
	"retune/internal/agent/state"
	"retune/internal/protocol"
)

var now = time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)

func opts(mutate func(*protocol.AppOptions)) protocol.AppOptions {
	o := protocol.DefaultAppOptions()
	if mutate != nil {
		mutate(&o)
	}
	return o
}

func uninstall() protocol.AppOptions {
	return opts(func(o *protocol.AppOptions) { o.Intent = protocol.IntentUninstall })
}

func TestDecide(t *testing.T) {
	cases := map[string]struct {
		version int
		opts    protocol.AppOptions
		state   state.AppState
		want    apps.Action
	}{
		"never seen before": {
			version: 1, opts: opts(nil), state: state.AppState{},
			want: apps.ActionDetect,
		},
		"a new version is a fresh instruction": {
			version: 2, opts: opts(nil),
			state: state.AppState{Version: 1, Installed: true, LastSeenAt: now, LastActedAt: now},
			want:  apps.ActionDetect,
		},
		"installed and checked recently: nothing to do": {
			version: 1, opts: opts(nil),
			state: state.AppState{Version: 1, Installed: true, LastSeenAt: now.Add(-10 * time.Minute)},
			want:  apps.ActionNone,
		},
		"installed but not checked for an hour": {
			version: 1, opts: opts(nil),
			state: state.AppState{Version: 1, Installed: true, LastSeenAt: now.Add(-90 * time.Minute)},
			want:  apps.ActionDetect,
		},
		"detected missing, so put it back": {
			version: 1, opts: opts(nil),
			state: state.AppState{Version: 1, Installed: false, LastSeenAt: now},
			want:  apps.ActionInstall,
		},
		"uninstall intent with it present": {
			version: 1, opts: uninstall(),
			state: state.AppState{Version: 1, Installed: true, LastSeenAt: now},
			want:  apps.ActionUninstall,
		},
		"uninstall intent with it already gone": {
			version: 1, opts: uninstall(),
			state: state.AppState{Version: 1, Installed: false, LastSeenAt: now, Intent: protocol.IntentUninstall},
			want:  apps.ActionNone,
		},
		"a changed intent is acted on at once": {
			version: 1, opts: uninstall(),
			state: state.AppState{Version: 1, Intent: protocol.IntentInstall, Installed: true, LastSeenAt: now},
			want:  apps.ActionUninstall,
		},
		"it has failed too often to keep trying": {
			version: 1, opts: opts(nil),
			state: state.AppState{
				Version: 1, Installed: false, LastSeenAt: now, LastActedAt: now,
				LastStatus: protocol.ResultFailed, Failures: 3,
			},
			want: apps.ActionNone,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := apps.Decide(tc.version, tc.opts, tc.state, now)
			if got.Action != tc.want {
				t.Fatalf("action = %v, want %v (reason %q)", got.Action, tc.want, got.Reason)
			}
			if got.Action == apps.ActionNone && got.Reason == "" {
				t.Error("a decision to do nothing should say why, for the agent's log")
			}
		})
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/agent/apps/ -run TestDecide -count=1`

Expected: FAIL to compile — `apps.Decide` does not exist.

- [ ] **Step 3: Add the state accessors**

In `internal/agent/state/state.go`, add `bucketApps = []byte("apps")` to the `var` block **and to the list in `Open`**, then add `AppState`, `(s *Store) AppState(id string)` and `(s *Store) SetAppState(id string, st AppState)` modelled on `ItemState`/`SetItemState`. Apps get their own bucket rather than sharing `bucketItems`, which is keyed by bare item ID: re-keying that bucket would orphan every deployed agent's script state and re-run every script once.

- [ ] **Step 4: Write `Decide`**

Create `internal/agent/apps/scheduler.go`. It is a pure function, as `scripts.Decide` is — no winget, no filesystem, no clock of its own:

```go
// DetectEvery is how often an app that is already in the right state is
// checked again. Retune does not chase upstream releases, but it does notice
// when somebody has removed software that was assigned.
const DetectEvery = time.Hour

// Decide reports what to do about one assigned app. It is deliberately a pure
// function: every rule is decided from the version, the options, what the
// agent remembers and the clock, so all of it is testable without winget.
func Decide(version int, opts protocol.AppOptions, st state.AppState, now time.Time) Decision {
	// A new version or a changed intent is a fresh instruction, so neither the
	// old failures nor the old detection hold it back.
	fresh := st.Version != version || st.Intent != opts.Intent
	if fresh || st.LastSeenAt.IsZero() {
		return Decision{Action: ActionDetect}
	}
	if st.Failures > 0 && st.Failures >= maxAttempts {
		return Decision{Reason: "this version has failed too many times"}
	}

	want := opts.Intent == protocol.IntentInstall
	if st.Installed != want {
		if want {
			return Decision{Action: ActionInstall}
		}
		return Decision{Action: ActionUninstall}
	}
	if now.Sub(st.LastSeenAt) >= DetectEvery {
		return Decision{Action: ActionDetect}
	}
	return Decision{Reason: "it is already in the right state"}
}
```

`maxAttempts` is an unexported `const maxAttempts = 3` with a comment saying a package that will not install is usually a problem with the package, not the machine, so retrying forever only fills the log.

- [ ] **Step 5: Run the tests**

Run: `go test ./internal/agent/apps/ ./internal/agent/state/ -count=1`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/agent/apps/scheduler.go internal/agent/apps/scheduler_test.go internal/agent/state/state.go
git commit -m "feat(agent): decide what an assigned app needs"
```

---

### Task 11: Acting on the decision

**Files:**
- Create: `internal/agent/apps/syncer.go`
- Create: `internal/agent/apps/syncer_test.go`
- Modify: `internal/agent/session/session.go` — an `Apps` field, a client adapter, an `ItemSyncer` adapter
- Modify: `internal/agent/runner/runner.go` — construct it
- Modify: `internal/agent/client/client.go` — `FetchApp`, `ReportAppResult`

**Interfaces:**
- Consumes: Tasks 9 and 10, `session.ItemSyncer` from Task 3.
- Produces:
  ```go
  type Client interface {
      FetchApp(ctx context.Context, id string, version int) (protocol.AppVersionResponse, error)
      ReportAppResult(ctx context.Context, id string, r protocol.AppResult) error
  }
  type Syncer struct {
      State *state.Store; Client Client; Winget Winget
      Log *slog.Logger; Now func() time.Time
      mu sync.Mutex
  }
  func (s *Syncer) Sync(ctx context.Context, items []protocol.Item) error
  ```

- [ ] **Step 1: Write the failing test**

Create `internal/agent/apps/syncer_test.go` with a fake winget in the shape of the M6 `fakeRunner`:

```go
package apps_test

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"retune/internal/agent/apps"
	"retune/internal/agent/state"
	"retune/internal/protocol"
)

// fakeWinget answers with canned results, so installs can be tested without
// installing anything.
type fakeWinget struct {
	mu        sync.Mutex
	installed bool
	version   string
	calls     []string
	installErr int // exit code the install should produce
}

func (f *fakeWinget) Detect(context.Context, string) (bool, string, apps.Result) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "detect")
	return f.installed, f.version, apps.Result{}
}

func (f *fakeWinget) Install(context.Context, protocol.AppVersionResponse) apps.Result {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "install")
	if f.installErr == 0 {
		f.installed, f.version = true, "26.03"
	}
	return apps.Result{ExitCode: f.installErr}
}

func (f *fakeWinget) Uninstall(context.Context, string) apps.Result {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "uninstall")
	f.installed, f.version = false, ""
	return apps.Result{}
}

func (f *fakeWinget) ran() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

type fakeClient struct {
	version protocol.AppVersionResponse
	results []protocol.AppResult
}

func (c *fakeClient) FetchApp(context.Context, string, int) (protocol.AppVersionResponse, error) {
	return c.version, nil
}

func (c *fakeClient) ReportAppResult(_ context.Context, _ string, r protocol.AppResult) error {
	c.results = append(c.results, r)
	return nil
}

func newSyncer(t *testing.T, c *fakeClient, w apps.Winget) (*apps.Syncer, *state.Store) {
	t.Helper()
	st, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return &apps.Syncer{
		State: st, Client: c, Winget: w, Now: func() time.Time { return now },
	}, st
}

func item(id string, version int, o protocol.AppOptions) protocol.Item {
	raw, err := o.Marshal()
	if err != nil {
		panic(err)
	}
	return protocol.Item{Kind: protocol.ItemKindApp, ID: id, Version: version, Options: raw}
}

// A missing app is detected and then installed, and the result says which
// version landed.
func TestInstallsWhatIsMissing(t *testing.T) {
	c := &fakeClient{version: protocol.AppVersionResponse{
		Version: 1, PackageID: "7zip.7zip", Scope: "machine",
	}}
	w := &fakeWinget{}
	s, _ := newSyncer(t, c, w)

	if err := s.Sync(context.Background(), []protocol.Item{item("a1", 1, opts(nil))}); err != nil {
		t.Fatal(err)
	}
	if got := w.ran(); len(got) < 2 || got[0] != "detect" || got[1] != "install" {
		t.Fatalf("it should detect then install, got %v", got)
	}
	if len(c.results) != 1 {
		t.Fatalf("one result should be reported, got %+v", c.results)
	}
	if c.results[0].Status != protocol.ResultSucceeded || c.results[0].InstalledVersion != "26.03" {
		t.Errorf("result = %+v", c.results[0])
	}
}

// Something already installed is not installed again, and nothing is reported:
// there is no news.
func TestLeavesAnInstalledAppAlone(t *testing.T) {
	c := &fakeClient{version: protocol.AppVersionResponse{
		Version: 1, PackageID: "7zip.7zip", Scope: "machine",
	}}
	w := &fakeWinget{installed: true, version: "26.03"}
	s, _ := newSyncer(t, c, w)

	it := item("a1", 1, opts(nil))
	if err := s.Sync(context.Background(), []protocol.Item{it}); err != nil {
		t.Fatal(err)
	}
	// A second cycle immediately afterwards does not even detect again.
	if err := s.Sync(context.Background(), []protocol.Item{it}); err != nil {
		t.Fatal(err)
	}
	for _, call := range w.ran() {
		if call == "install" {
			t.Fatalf("it must not reinstall what is present, got %v", w.ran())
		}
	}
	if len(w.ran()) != 1 {
		t.Errorf("the second cycle should not detect again within the hour, got %v", w.ran())
	}
}

// Uninstall intent removes it and reports that it went.
func TestUninstallIntentRemovesIt(t *testing.T) {
	c := &fakeClient{version: protocol.AppVersionResponse{
		Version: 1, PackageID: "7zip.7zip", Scope: "machine",
	}}
	w := &fakeWinget{installed: true, version: "26.03"}
	s, _ := newSyncer(t, c, w)

	if err := s.Sync(context.Background(), []protocol.Item{item("a1", 1, uninstall())}); err != nil {
		t.Fatal(err)
	}
	if len(c.results) != 1 || c.results[0].Intent != protocol.IntentUninstall {
		t.Fatalf("an uninstall should be reported as one, got %+v", c.results)
	}
	if c.results[0].Status != protocol.ResultSucceeded {
		t.Errorf("result = %+v", c.results[0])
	}
}

// A failed install is reported as failed, with the exit code, and the app is
// not recorded as installed.
func TestReportsAFailedInstall(t *testing.T) {
	c := &fakeClient{version: protocol.AppVersionResponse{
		Version: 1, PackageID: "7zip.7zip", Scope: "machine",
	}}
	w := &fakeWinget{installErr: 1}
	s, st := newSyncer(t, c, w)

	if err := s.Sync(context.Background(), []protocol.Item{item("a1", 1, opts(nil))}); err != nil {
		t.Fatal(err)
	}
	if len(c.results) != 1 || c.results[0].Status != protocol.ResultFailed {
		t.Fatalf("a failed install should be reported as one, got %+v", c.results)
	}
	if c.results[0].ExitCode != 1 {
		t.Errorf("the exit code should survive, got %+v", c.results[0])
	}
	local, err := st.AppState("a1")
	if err != nil {
		t.Fatal(err)
	}
	if local.Installed {
		t.Error("a failed install must not be remembered as installed")
	}
	if local.Failures != 1 {
		t.Errorf("failures = %d, want 1", local.Failures)
	}
}

// An item of another kind is ignored, which is how an older agent copes with a
// newer server.
func TestIgnoresOtherKinds(t *testing.T) {
	c := &fakeClient{}
	w := &fakeWinget{}
	s, _ := newSyncer(t, c, w)

	err := s.Sync(context.Background(), []protocol.Item{{Kind: "script", ID: "s1", Version: 1}})
	if err != nil {
		t.Fatal(err)
	}
	if len(w.ran()) != 0 {
		t.Fatalf("nothing should have happened, got %v", w.ran())
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/agent/apps/ -count=1`

Expected: FAIL to compile — `apps.Syncer` does not exist.

- [ ] **Step 3: Write the syncer**

Create `internal/agent/apps/syncer.go`, modelled on `internal/agent/scripts/runner.go`:

- `Sync` takes `s.mu` for the whole call — concurrent winget invocations conflict with each other — filters to `protocol.ItemKindApp`, and logs and continues past one failing app so the rest still run.
- `syncOne` parses options, reads `state.AppState`, calls `Decide`, and returns early on `ActionNone`.
- On `ActionDetect` it detects, writes the refreshed state, and then **re-decides once** so a detection that finds the app missing installs it in the same cycle. That second decision is not allowed to detect again.
- Install and uninstall run under `context.WithTimeout(ctx, opts.Timeout())`.
- **State is written before the result is reported**, so a server that cannot be reached does not cause a reinstall next cycle.
- A detection that changes nothing reports nothing: there is no news, and reporting every hour would fill the install history with noise.
- `classify` decides the reported status; `OutcomeRebootRequired` reports `ResultSucceeded` with `Detail` saying a restart is needed to finish.

- [ ] **Step 4: Wire it in**

Add `FetchApp` and `ReportAppResult` to `internal/agent/client/client.go` beside `FetchScript`/`ReportScriptRun`, hitting `/api/agent/v1/apps/{id}/versions/{version}` and `/api/agent/v1/apps/{id}/result`.

In `internal/agent/session/session.go`: add `Apps *apps.Syncer` to `Config`, an `appClient{s}` adapter routing through `s.currentClient()`, wire `cfg.Apps.Client` in `New` the way `cfg.Scripts.Client` is wired, and add

```go
// appSyncer adapts the app syncer. Like scripts, it is not called with an
// empty item list: an app that is no longer assigned stays installed until
// somebody assigns it with uninstall intent.
type appSyncer struct{ s *apps.Syncer }

func (a appSyncer) Sync(ctx context.Context, items []protocol.Item) error {
	return a.s.Sync(ctx, items)
}
func (appSyncer) RunOnEmpty() bool { return false }
func (appSyncer) Name() string     { return "assigned apps" }
```

appending it to `s.cfg.Syncers` alongside the other two.

In `internal/agent/runner/runner.go`, construct it beside the scheduler. `apps.New()` returns `ErrNoAppInstaller` on a machine without winget; log that at info and leave `Apps` nil rather than failing to start, because every other part of the agent still works:

```go
	var appSyncer *apps.Syncer
	if wg, err := apps.New(); err != nil {
		opts.Log.Info("app deployments are unavailable on this machine", "error", err)
	} else {
		appSyncer = &apps.Syncer{State: st, Winget: wg, Log: opts.Log, Now: time.Now}
	}
```

and pass `Apps: appSyncer` in the `session.Config`. Guard the `Syncers` append in `New` with `cfg.Apps != nil`.

- [ ] **Step 5: Run the tests**

Run: `go test ./internal/agent/... -count=1 && go vet ./... && GOOS=linux go build ./...`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/agent/apps/ internal/agent/session/session.go internal/agent/runner/runner.go internal/agent/client/client.go
git commit -m "feat(agent): install and remove assigned apps"
```

---

### Task 12: The Apps page

**Files:**
- Create: `web/src/pages/Apps.tsx`, `web/src/pages/Apps.css`, `web/src/pages/Apps.test.tsx`
- Modify: `web/src/api/types.ts`, `web/src/App.tsx`, `web/src/components/Shell.tsx`

**Interfaces:**
- Consumes: the Task 7 admin routes, `api.get/post/del`, `useList`, `StatusDot`, `Button`/`Dialog`/`EmptyState`/`ErrorNote`/`Field`/`Spinner` from `../components/ui`.
- Produces: `App` and `AppInstall` in `types.ts`; a default-exported `Apps()` page. There is no `AppVersion` type: the page does not show version history, and an unused interface is one more thing to keep true.

- [ ] **Step 1: Write the failing test**

Create `web/src/pages/Apps.test.tsx`, following the conventions in `Scripts.test.tsx` — `vi.mock` for `SessionContext` and `react-router-dom`, a `json()` helper, `fetchMock` on `globalThis.fetch`:

```tsx
const app = {
  id: "a1",
  name: "7-Zip",
  description: "archiver",
  package_id: "7zip.7zip",
  pinned_version: "",
  scope: "machine",
  current_version: 1,
  created_at: "2026-09-13T00:00:00Z",
  updated_at: "2026-09-13T00:00:00Z",
  created_by: "ops@example.com",
};

it("lists apps with the package they install", async () => {
  listOnly();
  render(<Apps />);
  expect(await screen.findByText("7-Zip")).toBeInTheDocument();
  expect(screen.getByText("7zip.7zip")).toBeInTheDocument();
});

it("warns that an uninstall assignment removes software", async () => {
  listOnly();
  render(<Apps />);
  await screen.findByText("7-Zip");

  await userEvent.click(screen.getByRole("button", { name: "Assign" }));
  await screen.findByLabelText("What to do");
  await userEvent.selectOptions(screen.getByLabelText("What to do"), "uninstall");

  expect(screen.getByText(/removes it from every device/i)).toBeInTheDocument();
});

it("sends the intent with the assignment", async () => {
  listOnly();
  render(<Apps />);
  await screen.findByText("7-Zip");

  await userEvent.click(screen.getByRole("button", { name: "Assign" }));
  await screen.findByLabelText("What to do");
  await userEvent.click(screen.getByRole("button", { name: "Assign to group" }));

  const call = fetchMock.mock.calls.find(([url]) => String(url).includes("/assignments"));
  expect(JSON.parse(String(call?.[1]?.body)).options).toMatchObject({ intent: "install" });
});
```

Write `listOnly()` to answer `/apps?` with the listing and `/groups` with one group, mirroring `Scripts.test.tsx`.

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm --prefix web run test -- --run Apps`

Expected: FAIL — `./Apps` cannot be resolved.

- [ ] **Step 3: Add the types**

In `web/src/api/types.ts`, beside `Script`:

```ts
export interface App {
  id: string;
  name: string;
  description: string;
  package_id: string;
  pinned_version?: string;
  scope?: string;
  install_args?: string;
  current_version: number;
  created_at: string;
  updated_at: string;
  created_by: string;
}

export interface AppInstall {
  id: string;
  device_id: string;
  hostname: string;
  version: number;
  intent: string;
  status: string;
  installed_version: string;
  exit_code: number;
  stdout: string;
  stderr: string;
  error: string;
  detail: string;
  started_at: string;
  finished_at: string;
}
```

- [ ] **Step 4: Write the page**

Create `web/src/pages/Apps.tsx` with `const ITEM_KIND = "app"`, modelled on `Scripts.tsx`:

- `AppEditor` — name, description, package ID, pinned version (blank meaning "whatever is current"), and extra install arguments. No scope control: machine is the only scope, and offering a choice of one is noise.
- `AssignDialog` — group, include/exclude, and a **"What to do"** select of install/uninstall. When uninstall is chosen the field carries the hint *"This removes it from every device in the group. Leaving the group does not."*
- `AppDetail` — the rollup from `/items/app/{id}/status` and history from `/apps/{id}/installs`, each row showing the intent, the status, which Retune version it refers to, and the installed version.

Register the route in `App.tsx` (`<Route path="/apps" element={<Apps />} />`) and the nav entry in `Shell.tsx` (`{ to: "/apps", label: "Apps" }`), placed after Scripts and before Profiles in both.

- [ ] **Step 5: Run the tests and the build**

Run: `npm --prefix web run test -- --run && npm --prefix web run build`

Expected: PASS, and a clean build. `tsc -b` is stricter than `tsc --noEmit`: unused parameters are errors, so prefix any with `_`.

- [ ] **Step 6: Commit**

```bash
git add web/src/pages/Apps.tsx web/src/pages/Apps.css web/src/pages/Apps.test.tsx web/src/api/types.ts web/src/App.tsx web/src/components/Shell.tsx
git commit -m "feat(console): an Apps page, with install and uninstall intent"
```

---

### Task 13: End to end, and the documentation

**Files:**
- Modify: `test/e2e/e2e_test.go`
- Modify: `README.md`
- Modify: `docs/superpowers/plans/2026-09-12-roadmap.md`

- [ ] **Step 1: Write the failing end-to-end test**

Read `test/e2e/e2e_test.go` first: it already has an end-to-end test that
creates a script, assigns it, checks in as an agent and reports a run. Mirror
that test's setup exactly -- the same server, admin client and device
enrollment helpers -- and replace its middle with the app flow below. The
setup differs between that file and `internal/server/app`, so copy from the
file you are adding to, not from this plan.

The assertions, which are the point of the test:

```go
	// The app reaches the agent at its current version.
	items := decodeJSON[protocol.CheckinResponse](t, body).Items
	if len(items) != 1 || items[0].Kind != protocol.ItemKindApp || items[0].Version != 1 {
		t.Fatalf("the app should be offered once, at version 1, got %+v", items)
	}

	// The agent can read the definition it was offered, and only that one.
	version := decodeJSON[protocol.AppVersionResponse](t, versionBody)
	if version.PackageID != "7zip.7zip" || version.Scope != "machine" {
		t.Fatalf("definition = %+v", version)
	}

	// What it reports settles the console's view of that device.
	if rollup[store.ItemSucceeded] != 1 {
		t.Fatalf("want one succeeded, got %v", rollup)
	}
	if !strings.Contains(detail, "26.03") {
		t.Errorf("the detail should name the version that landed, got %q", detail)
	}

	// Uninstall intent is a different instruction, not the absence of one.
	// Re-assigning with intent uninstall and reporting that result leaves the
	// device succeeded, with a detail that says it was removed.
	if !strings.Contains(afterRemoval, "removed") {
		t.Errorf("the detail should say it went, got %q", afterRemoval)
	}
```

Fill in the request plumbing around those assertions from the neighbouring
test. Do not leave any part of the body as a comment: a test that does not run
the flow proves nothing.

- [ ] **Step 2: Run it to verify it fails, then make it pass**

Run: `go test ./test/e2e/ -run TestAppDeploymentEndToEnd -count=1`

Expected: FAIL first, then PASS once the test is written correctly against the finished code. Nothing in the product should need changing — if it does, that is a real gap and worth stopping over.

- [ ] **Step 3: Document it**

Add an **Applications** section to `README.md` after the script deployments section:

```markdown
## Applications

Apps live under **Apps**. An app is a winget package — a package ID, and
optionally an exact version. Every change to what gets installed creates a new
immutable version; renaming or re-describing an app does not.

Assign one to a group and choose what to do:

| Option | Default | Meaning |
|---|---|---|
| What to do | install | `install`, or `uninstall` to remove it |
| Timeout | 900 seconds | per winget invocation, 60 to 14400 |

**Removal is deliberate.** A device that drops out of a group keeps the
software. To take something away, assign the app with uninstall intent — so a
dynamic group whose rule stops matching never quietly wipes software off
machines.

Retune installs what is missing and then leaves it alone: it does not upgrade
an app when a newer release appears upstream. Moving a fleet to a new version
means pinning one, which is a deliberate act with a version number attached.
It does re-check about once an hour, and puts back anything that has been
uninstalled, because an app assigned to a group should be on the machines in
that group.

Installs run as the system account, machine-wide. There is no per-user scope:
the agent is LocalSystem, so a user-scope install would land in the system
account's profile rather than anyone's.

A machine with no App Installer reports that plainly and installs nothing.
```

Also add a bullet to **What works today**:

```markdown
- **Application deployment.** winget packages assigned to groups, installed by
  the agent and removed on request, with per-device history.
```

Update `docs/superpowers/plans/2026-09-12-roadmap.md`: add the M9 row to the table and change the status line to say M1 through M9 are implemented and merged.

- [ ] **Step 4: Run everything**

Run:

```bash
gofmt -l . && go vet ./... && GOOS=linux go build ./... && go test ./... -count=1
npm --prefix web run test -- --run && npm --prefix web run build
```

Expected: all green, `gofmt -l` silent.

- [ ] **Step 5: Commit**

```bash
git add test/e2e/e2e_test.go README.md docs/superpowers/plans/2026-09-12-roadmap.md
git commit -m "test: app deployment end to end, and document it"
```

---

## Verification on this machine

After Task 13, prove it through the installed service the way M4, M7 and M8 were proven. This is not a task in the plan because it is not code; it is the acceptance check, and the spec's §10 is the authority.

1. Build, start a throwaway Postgres and a server, and install the agent service so it enrolls itself.
2. Create an app for **7-Zip** (`7zip.7zip`) and assign it to All devices. Confirm the service, running as LocalSystem, installs it and reports `succeeded` with the installed version.
3. Check in again. Confirm it is **not** reinstalled, and that no second install appears in the history.
4. Assign uninstall intent. Confirm 7-Zip is removed and reported.
5. Uninstall the service, remove its data directory, stop the server and the database container.

7-Zip is small, silent-installable and self-contained, and the machine ends as it started. No other package is installed, and nothing already on the machine is upgraded or modified.
