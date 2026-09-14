# M9 — Application deployment

**Spec:** extends `docs/superpowers/specs/2026-09-12-core-platform-design.md`
(app deployment was listed there as out of scope for the core platform).

**Builds on:** M1–M8, all merged. Reuses the M5 assignment engine and the M6
agent scheduler almost entirely.

Retune can put software on a machine. An **app** is a winget package assigned
to a group; the agent installs it, notices when it has gone missing, and can
take it away again when told to.

## 1. Decisions

| Question | Decision | Why |
|---|---|---|
| Where do installers come from? | winget only. An app is a package ID, optionally pinned to a version. | winget already handles download, hash verification, silent install and uninstall. Hosting binaries would mean a file store, an upload API and an authenticated download path for agents — a milestone of its own, for software winget mostly already carries. |
| How is software removed? | Intent on the assignment: `install` or `uninstall`. Dropping out of a group does nothing. | A dynamic group whose rule stops matching would otherwise wipe software off machines with nobody having asked for it. Removing software should be something a person decided. |
| How is "already installed" decided? | `winget list --id <id> --exact`, by exit code. | winget is the same source of truth that installed it. No authoring burden, and the exit code is unambiguous where parsing stdout would not be. |
| Self-service catalogue? | No. Admin-pushed only. | A user-facing catalogue needs an endpoint app, a user-authenticated API and a per-user queue. It is a separate milestone, and nothing here forecloses it. |
| Upgrades? | Install if missing. Retune does not chase new upstream releases. | Software should not change under people on winget's schedule. A pinned version bump is how a fleet moves, and it is a deliberate act with a version number attached. |
| Reinstall if removed? | Yes — re-detect at most hourly per app, and always after an install. | "This group has 7-Zip" should mean it. A strict one-shot per version would let a single user uninstall defeat the deployment permanently. |
| Immutable versions? | Yes, as for scripts and profiles. | Per-device status says which version it refers to, so "succeeded" is never ambiguous after an edit. Renaming an app does not redeploy it. |
| A new item kind, or a profile setting? | A new item kind, `app`. | Apps need their own versions, their own install/uninstall intent and their own per-app history. Folding them into profiles would flatten all three and lose per-app assignment. |

## 2. What the probe established

Run as `NT AUTHORITY\SYSTEM` on a Windows 11 machine via a temporary scheduled
task, read-only, before any of this was designed:

- **winget runs as LocalSystem.** `winget` is absent from `PATH` there, because
  it ships as a per-user app-execution alias. Resolving
  `%ProgramFiles%\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe\winget.exe`
  found a working binary: `--version` returned `v1.29.290`, exit 0.
- **Detection is an exit code.** `winget list --id 7zip.7zip --exact` on a
  machine without it exits `-1978335212`
  (`APPINSTALLER_CLI_ERROR_NO_APPLICATIONS_FOUND`), not zero-with-no-output.
- **The `msstore` source injects an agreement prompt** even given
  `--accept-source-agreements`. Pinning `--source winget` avoids it, which is
  wanted regardless: the Store source sends the machine's geographic region
  upstream and cannot be installed from silently.
- **winget's output is already valid UTF-8 on a redirected pipe.** The probe's
  `©` displayed on the console as `┬⌐`, which looks like a decoding bug but
  isn't one: `0xC2 0xA9` is correct UTF-8 for `©`, and CP437 — the console's
  own rendering codepage — is what turns those two bytes into `┬⌐`. A
  redirected pipe gets no codepage translation from Windows; what the agent
  reads is the same UTF-8 bytes winget wrote. No transcode is applied, because
  adding one would corrupt data that is already correct.

## 3. Data model

### Tables — `internal/server/store/migrations/0008_apps.{up,down}.sql`

```
apps              id, tenant_id, name, description, current_version,
                  created_at, updated_at, created_by
app_versions      app_id, version, package_id, pinned_version, scope,
                  install_args, hash, created_at, created_by
                  PRIMARY KEY (app_id, version)
app_installs      id, device_id, tenant_id, app_id, version, intent,
                  status, exit_code, stdout, stderr, error,
                  started_at, finished_at
```

`app_versions` rows are immutable, like `script_versions`. `app_installs`
carries no foreign key on `app_id`, following `script_runs`: history outlives
the deletion of the thing it describes.

No change to `assignments`, `device_item_status` or their queries. They are
already kind-agnostic, `item_id` deliberately carries no foreign key so new
kinds can be added, and the statuses this milestone reports
(`succeeded`, `failed`, `pending`) are already in the `device_item_status`
CHECK constraint. **There is no migration to the shared tables.**

### Version content

A version is the definition, not the name:

| Field | Meaning |
|---|---|
| `package_id` | the winget package ID, e.g. `7zip.7zip`. Required. |
| `pinned_version` | an exact version, or empty for "whatever is current when it is first installed" |
| `scope` | `machine` only. See below. |
| `install_args` | extra arguments passed through to the installer, usually empty |

`Update` compares the hash of these four fields and only bumps
`current_version` when they actually change, so re-describing an app does not
redeploy it.

**Why machine scope only.** The agent is LocalSystem, so `--scope user` would
install into the SYSTEM account's profile rather than any real person's — the
software would land where nobody can run it. Per-user installation needs the
interactive-session machinery the agent gained for `run_as: logged_in_user`,
and deserves its own decision about which user gets the software on a machine
several people share. The column exists so that decision has somewhere to go;
this milestone writes `machine` and validates that nothing else is accepted.

### Assignment options — `protocol.AppOptions`

```json
{ "intent": "install", "timeout_seconds": 900 }
```

`intent` is `install` (default) or `uninstall`. `timeout_seconds` is 60–14400,
default 900 — installs are far slower than scripts. Parsed by
`protocol.ParseAppOptions`, following the `deployment.go` template exactly:
defaults, `DisallowUnknownFields` decode, `validate()`, `Marshal()`, and a
wrapped `ErrBadOptions`.

## 4. Generalising the two-kind seams

Three places in the existing code are written for exactly two item kinds. The
third kind is what exposes them, so they are generalised here rather than given
another branch. Each has a bug or a latent bug attached, so this is repair, not
tidying.

| Place | Today | Change |
|---|---|---|
| `internal/server/agentapi/handler.go` `checkin` | Two sequential `if it.Kind == …` blocks resolve `CurrentVersion` and `continue` past deleted items. An `app` item would be sent with `Version: 0` and no existence check. | A `map[string]func(ctx, store.Item) (version int, exists bool)` on the handler. The loop becomes kind-agnostic; an unknown kind is dropped, not shipped broken. |
| `internal/server/adminapi/groups.go` `createAssignment` | `switch req.ItemKind` with **no `default`**, so an assignment naming an unknown kind is accepted and silently stores empty options. | A `map[string]func(json.RawMessage) ([]byte, error)` of options parsers, with a `default` that returns 400. This fixes a live bug. |
| `internal/agent/session/session.go` `Checkin` | Two hardwired subsystem fields, each handed the full item slice, with differing "run when the list is empty" semantics expressed as hand-written branches. | An `ItemSyncer` interface — `Sync(ctx, []protocol.Item) error` and `RunOnEmpty() bool` — and a slice. Profiles return true (an empty list is exactly when an unassigned profile must revert); scripts and apps return false. |

**Deliberately not changed:** `internal/agent/state` keys `bucketItems` by bare
item ID with no kind namespace. Re-keying it would orphan every deployed
agent's script state and re-run every script once. Apps get their own bucket
instead, which costs nothing and risks nothing.

## 5. The agent

A new package `internal/agent/apps`, in three files mirroring
`internal/agent/scripts`.

### `winget.go` — finding and driving winget

Resolution: the newest directory matching
`%ProgramFiles%\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe`,
then `winget.exe` inside it. Resolved once per sync and cached. Absent means
this machine has no App Installer, which is reported as a failure naming that
plainly.

Every invocation carries `--exact --source winget --disable-interactivity
--accept-source-agreements`. Install adds `--scope <scope> --silent
--accept-package-agreements`, and `--version <v>` when pinned. Output is read
as UTF-8.

| Operation | Command |
|---|---|
| detect | `winget list --id <id>` |
| install | `winget install --id <id> [--version <v>] --scope <scope> --silent [install_args]` |
| uninstall | `winget uninstall --id <id> --silent` |

### Exit-code classification

One function, `classify(code int) outcome`, so this judgement lives in exactly
one place:

| Code | Meaning | Reported as |
|---|---|---|
| `0` | success | `succeeded` |
| `-1978335212` | no matching installed package | not installed — the detection signal, not a failure |
| `3010`, and winget's own reboot-required codes | installed, restart needed | `succeeded`, with the restart said in the detail |
| anything else | a real failure | `failed`, with stdout and stderr attached |

Rows one and two are observed facts from the probe. `3010` is the standard
Windows Installer "reboot required" code. Winget's own reboot-required codes
are taken from its documented return-code list during implementation, and the
table in the code cites each one it names. Any code not in the table is a plain
failure, which is the safe default: a machine reported as failed gets looked
at, one wrongly reported as succeeded does not.

### `scheduler.go` — a pure `Decide`

```go
func Decide(version int, opts protocol.AppOptions, st state.AppState, now time.Time) Decision
```

No database, no filesystem, no winget — so every scheduling rule is unit
tested without a machine, as `scripts.Decide` is. It answers:

- a new Retune version of the app is due, whatever the state
- an `install` app last seen succeeded is re-detected at most hourly
- an app detected missing is installed again
- an `uninstall` app already absent is `succeeded` with nothing to do
- a failed attempt retries, bounded the way M6 bounds script retries

### `syncer.go` — Sync, and one install at a time

Filters `resp.Items` to `kind == "app"`, fetches each version once and caches
it by `id:version`, and reconciles. A mutex serialises installs: concurrent
winget invocations conflict with each other. Local state is written **before**
the result is reported, so a server that is unreachable at the wrong moment
never causes a reinstall — the M6 rule.

`RunOnEmpty()` returns false. Apps are not reverted by falling out of a group.

## 6. API surface

### Admin — `internal/server/adminapi/apps.go`

```
GET    /api/admin/v1/apps                 list
POST   /api/admin/v1/apps                 create
GET    /api/admin/v1/apps/{id}            get, with current settings
POST   /api/admin/v1/apps/{id}            update (bumps version if content changed)
DELETE /api/admin/v1/apps/{id}            delete, and its assignments
GET    /api/admin/v1/apps/{id}/versions   version history
GET    /api/admin/v1/apps/{id}/installs   install history across devices
```

`POST /assignments` and `GET /items/app/{id}/status` need no new routes: both
are already kind-generic.

### Agent — `internal/server/agentapi/handler.go`

```
GET  /api/agent/v1/apps/{id}/versions/{version}   the definition to act on
POST /api/agent/v1/apps/{id}/result               report an install or uninstall
```

Both gate on `DeviceHasItem(ctx, device, "app", id)` before returning or
accepting anything, exactly as the script and profile endpoints do. Reported
output passes through the same `clamp()` the scripts service uses: NULs
stripped, capped at `protocol.MaxOutputBytes`, forced to valid UTF-8.

## 7. Console

`web/src/pages/Apps.tsx` with `ITEM_KIND = "app"`, one route in `App.tsx` and
one entry in `Shell.tsx`, following `Scripts.tsx` — the smaller and clearer of
the two existing pages.

- **List** — name, package ID, current version, assignment count
- **Editor** — name, description, package ID, optional pinned version, scope,
  extra install arguments
- **Assign dialog** — group, include or exclude, and **intent**, with the
  uninstall option saying plainly that it removes software from every device in
  the group
- **Detail** — the status rollup from `/items/app/{id}/status` and install
  history from `/apps/{id}/installs`, showing which version each result refers
  to

## 8. Failure modes

Each gets a named answer rather than a generic error, because the console shows
these to somebody trying to work out why a machine does not have the software:

| Failure | Reported |
|---|---|
| App Installer absent | `failed` — "this machine has no App Installer, so winget cannot run" |
| Package ID not found in the source | `failed`, naming the package ID |
| Install timed out | `failed`, saying the timeout and that the install may still be running |
| winget exited non-zero | `failed`, with the exit code and captured output |
| Restart required | `succeeded`, with the restart noted in the detail |
| Uninstall of something already absent | `succeeded`, nothing to do |

## 9. Testing

**Unit, no machine required:** `Decide` as a table covering every row in §5;
`classify` over each exit code; command-line construction, because M8 proved
argument quoting breaks on program paths containing spaces; `ParseAppOptions`
defaults, bounds and unknown-field rejection.

**Agent, with a fake winget** in the shape of the M8 firewall fake: install
succeeds, install fails, package missing then present, uninstall, timeout.

**Integration, against a real Postgres via testcontainers:** service CRUD and
the immutable-version rule; `RecordInstall` writing history and status in one
transaction; assignment options validation, including that an unknown item kind
is now refused; check-in delivering app items at the right version and dropping
deleted ones.

**E2E:** assign an app, check in, report a result, read the rollup.

## 10. Verification on this machine

Once built, proven through the installed service the way M4, M7 and M8 were:

1. Install the Retune service and let it enroll.
2. Assign **7-Zip** (`7zip.7zip`, machine scope) to the device. Confirm the
   service, running as LocalSystem, installs it and reports `succeeded` with
   the version it installed.
3. Confirm detection: a second cycle reports it present and does not reinstall.
4. Assign **uninstall** intent. Confirm 7-Zip is removed and reported.
5. Uninstall the service and remove its data directory.

7-Zip is small, silent-installable, self-contained and leaves nothing behind.
The machine ends as it started. No other package is installed, and nothing
already on the machine is upgraded or modified.
