# M7 — Configuration Profiles I Design

**Parent spec:** `docs/superpowers/specs/2026-09-12-core-platform-design.md` (section 10)
**Roadmap row:** `docs/superpowers/plans/2026-09-12-roadmap.md` — M7
**Builds on:** merged M1–M6.

## 1. Summary

A script deployment does something once. A configuration profile states how a
machine should *be*, and the agent keeps it that way: on every check-in it tests
each setting, fixes what has drifted, and reports what it found.

M7 builds the engine and four setting kinds — `registry`, `service`,
`local_group_members` and `file`. The remaining kinds (`firewall`,
`windows_update`, `bitlocker`) are M8, and the engine is built so they only have
to implement one interface.

## 2. Decisions

| Decision | Choice | Why |
|---|---|---|
| Reconcile loop | Test, then Set only if needed, then Test again | The second test is what distinguishes "I fixed it" from "I ran something". A handler that reports success without re-checking is guessing. |
| Conflict handling | Two profiles setting the same identity key to different values apply **neither**, and both report `conflict` | Picking a winner silently would make a machine's state depend on assignment order, which nobody can reason about. Identical values are not a conflict. |
| Setting identity | A canonical string per kind, e.g. `registry:HKLM\SOFTWARE\X!Value` | Conflicts are only detectable if two profiles naming the same thing produce the same key. |
| `HKCU` registry settings | Refused when the profile is saved | They need the signed-in user's loaded hive, which needs the interactive-session work M6 deferred. Refusing at save time beats letting someone build a profile that can only ever error on every device. |
| Revert | The agent records the prior state before its **first** `Set`, and restores it when the profile leaves and `revert_on_removal` is on | Reverting to a value read later would restore what Retune itself wrote. The prior state has to be captured before the first change and kept. |
| Status granularity | Per setting, rolled up per profile | "The profile failed" is not actionable. "`service:Spooler` errored: access denied" is. |
| Handler side effects | Behind a narrow `system` interface per handler | Registry writes, service control and group membership cannot be exercised in an ordinary unit test; an interface lets the engine's logic be tested exhaustively and keeps the untestable part small enough to read. |
| Ordering | Settings apply in the order written in the profile | An administrator who writes a file and then starts a service that reads it expects that order. Sorting them would be surprising. |

## 3. The profile model

A profile is a name, a description, and an ordered list of settings, versioned
exactly like a script: every edit to the settings creates a new immutable
version; renaming does not.

A setting is an object with a `kind` and the fields that kind needs:

```json
{
  "settings": [
    {"kind": "registry", "hive": "HKLM", "key": "SOFTWARE\\Retune", "name": "Managed",
     "type": "REG_DWORD", "data": "1"},
    {"kind": "service", "name": "Spooler", "startup": "disabled", "state": "stopped"},
    {"kind": "local_group_members", "group": "Administrators",
     "members": ["CONTOSO\\Helpdesk"], "mode": "additive"},
    {"kind": "file", "path": "C:/ProgramData/Retune/motd.txt",
     "content_base64": "aGk=", "ensure": "present"}
  ]
}
```

Settings are validated when the profile is saved, so an agent never meets a
setting it cannot parse. Assignment options are `{"revert_on_removal": false}`.

## 4. Setting kinds in M7

| Kind | Fields | Identity key |
|---|---|---|
| `registry` | `hive` (`HKLM` only in M7), `key`, `name`, `type` (`REG_SZ`, `REG_DWORD`, `REG_QWORD`, `REG_MULTI_SZ`, `REG_EXPAND_SZ`), `data`, or `ensure: absent` | `registry:HKLM\<key>!<name>` |
| `service` | `name`, `startup` (`automatic`, `manual`, `disabled`), `state` (`running`, `stopped`) | `service:<name>` |
| `local_group_members` | `group`, `members`, `mode` (`additive`, `exact`) | `local_group_members:<group>` |
| `file` | `path`, `content_base64`, `ensure` (`present`, `absent`) | `file:<normalised path>` |

Keys, service names and group names compare case-insensitively in the identity
key, because Windows treats them that way and two profiles differing only in
case are the same setting.

`exact` mode on `local_group_members` **never removes the built-in
Administrator account**, whatever the profile says. Locking every administrator
out of a machine is not a configuration a management tool should carry out.

A `file` setting is capped at 1 MB, like every other body in this system.

## 5. The engine

`internal/agent/policy`:

```go
// State is what a handler found, kept so a setting can be reverted to it.
type State struct {
    Exists bool            `json:"exists"`
    Data   json.RawMessage `json:"data,omitempty"`
}

// Handler applies one kind of setting.
type Handler interface {
    Kind() string
    // Get reports the current state, used to record what to revert to.
    Get(ctx context.Context, spec Spec) (State, error)
    // Test reports whether the machine already matches the setting.
    Test(ctx context.Context, spec Spec) (bool, error)
    // Set makes it match.
    Set(ctx context.Context, spec Spec) error
}

// Reverter is implemented by handlers that can undo a setting.
type Reverter interface {
    Revert(ctx context.Context, spec Spec, prior State) error
}
```

Reconciling one check-in:

1. Collect every setting from every assigned profile, in order.
2. Group by identity key. A key claimed by two settings whose canonical form
   differs is a **conflict**: neither is applied, and every profile involved
   reports `conflict` for it, naming the others.
3. For each remaining setting: `Test`. If it passes, report `compliant`.
   Otherwise record the prior state if this is the first time, `Set`, then
   `Test` again — `remediated` if it now passes, `error` if it does not, or if
   any step failed.
4. Compare the assigned profiles with the ones last seen. For any that have
   gone, stop enforcing, and if `revert_on_removal` was set and the handler is
   a `Reverter`, restore the recorded prior state.
5. Report every setting's status.

A handler that panics is recovered and reported as an error for that setting
only: one bad setting must not stop a profile, and one bad profile must not stop
a check-in.

## 6. What the agent is told

Profiles reuse M5's assignment machinery and M6's item shape, so check-in needs
nothing new: `Item{Kind: "profile", ID, Version, Options}`. The settings are
fetched per version and cached, exactly as script bodies are:

```
GET  /api/agent/v1/profiles/{id}/versions/{version}   -> { version, settings, hash }
POST /api/agent/v1/profiles/{id}/status               -> per-setting results
```

Both require the device certificate, and the `GET` is refused unless the profile
is assigned to that device.

## 7. Data model

Migration `0006_profiles`:

```sql
CREATE TABLE profiles (
    id              uuid PRIMARY KEY,
    tenant_id       uuid NOT NULL REFERENCES tenants(id),
    name            text NOT NULL,
    description     text NOT NULL DEFAULT '',
    current_version integer NOT NULL DEFAULT 0,
    created_at      timestamptz NOT NULL,
    updated_at      timestamptz NOT NULL,
    created_by      text NOT NULL
);
CREATE UNIQUE INDEX profiles_name ON profiles (tenant_id, lower(name));

CREATE TABLE profile_versions (
    profile_id uuid NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    version    integer NOT NULL,
    tenant_id  uuid NOT NULL REFERENCES tenants(id),
    settings   jsonb NOT NULL,
    hash       text NOT NULL,
    created_at timestamptz NOT NULL,
    created_by text NOT NULL,
    PRIMARY KEY (profile_id, version)
);

-- One row per setting per device: "the profile failed" is not actionable.
CREATE TABLE profile_setting_status (
    device_id  uuid NOT NULL REFERENCES devices(id),
    tenant_id  uuid NOT NULL REFERENCES tenants(id),
    profile_id uuid NOT NULL,
    identity   text NOT NULL,
    version    integer NOT NULL,
    status     text NOT NULL CHECK (status IN ('compliant', 'remediated', 'error', 'conflict')),
    detail     text NOT NULL DEFAULT '',
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (device_id, profile_id, identity)
);
CREATE INDEX profile_setting_status_profile ON profile_setting_status (tenant_id, profile_id, status);
```

The profile's own `device_item_status` row rolls these up: `succeeded` when
every setting is compliant or remediated, `conflict` if any conflicts, and
`failed` if any errored.

## 8. Console

A Profiles page: the library, an editor listing settings with the fields each
kind needs, version history, assignment to groups with `revert_on_removal`, and
a rollup that drills into which setting is failing on which device — because
that is the question an administrator actually has.

## 9. Verification

Handlers act on real Windows, so they are verified against deliberately
harmless targets on the development machine: a key under
`HKLM\SOFTWARE\RetuneTest`, the Print Spooler service (stopped and restored),
a `RetuneTestGroup` created and deleted, and files under a temp directory.
Nothing pre-existing is modified, and everything is undone.

## 10. Out of scope

`firewall`, `windows_update` and `bitlocker` settings, `HKCU` registry values,
profile import or export, and any setting kind for macOS or Linux.
