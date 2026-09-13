# M6 — Script Deployments Design

**Parent spec:** `docs/superpowers/specs/2026-09-12-core-platform-design.md` (section 9)
**Roadmap row:** `docs/superpowers/plans/2026-09-12-roadmap.md` — M6
**Builds on:** merged M1–M5.

## 1. Summary

M6 gives `item_kind` its first real meaning. A script lives in a library with
immutable versions, is assigned to groups through the M5 assignment machinery,
and the agent decides on its own when to run it, reporting every run.

The difference from the ad-hoc `run_powershell` command is intent. A command is
a one-off: queued for a device, run once, forgotten. A deployment is a standing
statement about a fleet — "every workstation should have this" — that keeps
applying as machines join the group, come back online, or receive a new version
of the script.

## 2. Decisions

| Decision | Choice | Why |
|---|---|---|
| `run_as` | `system` only in M6; `logged_in_user` is stored and reported `pending` with a reason | Launching in a user's session from LocalSystem needs Win32 token work that no unit test can cover. Storing the intent and saying plainly that it is not yet supported beats either dropping the field or pretending it works. |
| Reporting | Every run in `script_runs`, latest state in `device_item_status` | Without history a script that fails every other run looks identical to one that failed once. |
| Scheduling | The agent decides, from its own local state | The server would otherwise have to track per-device timers for every script, and a device that is offline for a week would come back to a queue of missed runs rather than one. |
| Script body delivery | Check-in names the script and version; the agent fetches the body once per version and caches it | Check-in happens every five minutes and bodies do not change. Sending them each time would be wasteful, and a hash comparison per check-in still costs a round trip. |
| Conflicting options | The most recently created include assignment wins | The same script reaching a device through two groups is normal and harmless. A `conflict` status here would stop work over a difference that is usually accidental; the console shows which assignment supplied the options. |
| Detection outcome | Detection's second run decides success | Straight from the parent spec. Remediation's own exit code is recorded but does not determine the outcome, because a remediation that "succeeds" while leaving the machine non-compliant is a failure. |
| Versioning | Every edit writes a new immutable `script_versions` row | A run is only meaningful if you know exactly what ran. Mutable bodies make history a lie. |

## 3. The script library

A script has a name, a description, and a current version. Every edit creates a
new version; versions are never modified or deleted while the script exists.

A version holds:

- `body` — the PowerShell that does the work.
- `detection_body` — optional. When present, this is a detect-and-remediate
  pair: the detection script decides whether the work is needed.
- `hash` — SHA-256 of the two bodies, matching the pattern
  `protocol.InventoryHash` already uses.

Deleting a script deletes its versions and assignments. Its runs are kept: what
happened on a machine remains true after the script is gone.

## 4. Assignment options

M5 deliberately left `assignments` without an options column, because the items
being configured did not exist yet. Migration 0005 adds
`options jsonb NOT NULL DEFAULT '{}'`:

```json
{
  "frequency": "once",
  "interval_hours": 24,
  "run_as": "system",
  "timeout_seconds": 600,
  "max_retries": 2,
  "rerun_on_new_version": true
}
```

| Option | Default | Meaning |
|---|---|---|
| `frequency` | `once` | `once` or `recurring` |
| `interval_hours` | `24` | how often, when recurring; at least 1 |
| `run_as` | `system` | `system`, or `logged_in_user` (see the decision above) |
| `timeout_seconds` | `600` | per script execution; 1 to 86400 |
| `max_retries` | `2` | consecutive failures before the agent stops retrying this version |
| `rerun_on_new_version` | `true` | whether a new version runs again on a device that already ran an older one |

Options are validated on the server when an assignment is created, so an agent
never has to defend itself against nonsense.

## 5. What the agent is told

`protocol.Item` gains the fields a scheduler needs, and nothing more:

```go
type Item struct {
    Kind    string          `json:"kind"`
    ID      string          `json:"id"`
    Version int             `json:"version,omitempty"`
    Options json.RawMessage `json:"options,omitempty"`
}
```

The body is fetched separately:

```
GET  /api/agent/v1/scripts/{id}/versions/{version}   -> { body, detection_body, hash }
POST /api/agent/v1/scripts/{id}/runs                 -> records one run
```

Both require the device certificate, and the `GET` is refused unless that
script is actually assigned to that device: a device may only read what it has
been given.

## 6. How the agent decides to run

A new bbolt bucket, `items`, records per script: the version last run, when it
last ran, its last status, and how many times it has failed in a row.

On each check-in, for every item of kind `script`:

1. **`run_as: logged_in_user`** — report `pending`, detail "running as the
   logged-in user is not supported yet", and stop. Nothing is executed.
2. **Already running** — skip; one script runs at a time per device.
3. **Too many failures** — if the version is unchanged and consecutive failures
   have reached `max_retries`, skip. A new version clears the count, because a
   new version is a new attempt at the problem.
4. **`once`** — run if this version has never run here, or if the version
   changed and `rerun_on_new_version` is set.
5. **`recurring`** — run if `interval_hours` have passed since the last run, or
   on the same version rules as `once`.

Then, with the body fetched and cached for that version:

- **No detection**: run the body. Exit 0 succeeds; anything else fails.
- **With detection**: run detection. Exit 0 means there is nothing to do, and
  the run is recorded as succeeded with no remediation. Otherwise run the body,
  then run detection again — **that second detection's exit code decides**.

Every one of those paths reports a run. A device that skips reports nothing,
because nothing happened.

The agent keeps its existing safety properties: output capped at 1 MB per
stream, a per-run timeout, panics recovered, results queued locally and flushed
when the server is reachable.

## 7. Data model

Migration `0005_scripts`:

```sql
CREATE TABLE scripts (
    id              uuid PRIMARY KEY,
    tenant_id       uuid NOT NULL REFERENCES tenants(id),
    name            text NOT NULL,
    description     text NOT NULL DEFAULT '',
    current_version integer NOT NULL DEFAULT 0,
    created_at      timestamptz NOT NULL,
    updated_at      timestamptz NOT NULL,
    created_by      text NOT NULL
);
CREATE UNIQUE INDEX scripts_name ON scripts (tenant_id, lower(name));

-- Versions are immutable: a run is only meaningful if you know what ran.
CREATE TABLE script_versions (
    script_id      uuid NOT NULL REFERENCES scripts(id) ON DELETE CASCADE,
    version        integer NOT NULL,
    tenant_id      uuid NOT NULL REFERENCES tenants(id),
    body           text NOT NULL,
    detection_body text NOT NULL DEFAULT '',
    hash           text NOT NULL,
    created_at     timestamptz NOT NULL,
    created_by     text NOT NULL,
    PRIMARY KEY (script_id, version)
);

-- Kept when the script is deleted: what happened on a machine stays true.
CREATE TABLE script_runs (
    id               uuid PRIMARY KEY,
    tenant_id        uuid NOT NULL REFERENCES tenants(id),
    script_id        uuid NOT NULL,
    version          integer NOT NULL,
    device_id        uuid NOT NULL REFERENCES devices(id),
    status           text NOT NULL CHECK (status IN ('succeeded', 'failed', 'timed_out')),
    -- Which phase produced the outcome, so a failure can be read at a glance.
    phase            text NOT NULL CHECK (phase IN ('script', 'detection', 'remediation')),
    remediated       boolean NOT NULL DEFAULT false,
    exit_code        integer NOT NULL,
    stdout           text NOT NULL DEFAULT '',
    stderr           text NOT NULL DEFAULT '',
    stdout_truncated boolean NOT NULL DEFAULT false,
    stderr_truncated boolean NOT NULL DEFAULT false,
    error            text NOT NULL DEFAULT '',
    started_at       timestamptz NOT NULL,
    finished_at      timestamptz NOT NULL
);
CREATE INDEX script_runs_recent ON script_runs (script_id, device_id, started_at DESC);

ALTER TABLE assignments ADD COLUMN options jsonb NOT NULL DEFAULT '{}';

-- Which version the latest status refers to, so the console can say
-- "succeeded on version 3" rather than just "succeeded".
ALTER TABLE device_item_status ADD COLUMN version integer NOT NULL DEFAULT 0;
```

`script_runs.script_id` has no foreign key, so runs outlive the script.

## 7a. Ad-hoc commands stay as they are

`run_powershell` commands are untouched. They remain the right tool for "do
this now, once, on these machines", and the console keeps offering them.

## 8. Console

A Scripts page: the library, an editor for the body and the optional detection
script, the version history, which groups it is assigned to with their options,
and the rollup of how the fleet is faring, drilling into a device's last run
with its output.

## 9. Out of scope

Running as the logged-in user, script parameters or arguments, scripts in any
language but PowerShell, per-assignment schedules beyond an interval, and
importing scripts from a file or gallery.
