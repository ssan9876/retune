# M5 — Groups and Assignments Design

**Parent spec:** `docs/superpowers/specs/2026-09-12-core-platform-design.md` (sections 7, 8)
**Roadmap row:** `docs/superpowers/plans/2026-09-12-roadmap.md` — M5
**Builds on:** merged M1–M4.

## 1. Summary

M5 is how a fleet stops being a flat list. Devices go into groups, either by
explicit membership or by a rule evaluated over their inventory, and items are
assigned to groups with include and exclude modes. Each device's effective set
of items is computed on check-in.

There are no item kinds yet — scripts arrive in M6 and configuration profiles
in M7 — so assignments in M5 carry an opaque `(item_kind, item_id)` pair. That
is deliberate: the assignment machinery and the effective-set rules are the
hard part, and building them once means M6 and M7 only register a new kind.

## 2. Decisions

| Decision | Choice | Why |
|---|---|---|
| Rule parsing | Hand-written lexer and recursive-descent parser to an AST | The grammar is small and fixed. A parser dependency would be more code to audit than the parser. |
| Rule compilation | AST to parameterized SQL, field names from a fixed allowlist | Literals only ever become `$n` placeholders, so a rule cannot reach a column it was not granted, and cannot inject SQL. |
| Version comparison | Ordering compares dotted-numeric versions as `int[]`; equality compares text | Text ordering is simply wrong: `"1.10.0" < "1.9.0"` lexically. Versions that are not dotted-numeric do not match ordering tests, which is documented rather than silently false. |
| Dynamic membership | Materialized in `group_members`, refreshed on inventory change and every 15 minutes | The spec requires both triggers. Materializing keeps the check-in query a plain join instead of running every group's rule per check-in. |
| Effective-set cache | **Deviation: no cache.** Computed by one indexed query per check-in | Section 8 asks for a per-device cache invalidated by membership, assignment and item changes. Three invalidation triggers is a reliable source of stale-state bugs, and nothing has measured the query as too slow. The computation sits behind one function, so a cache can be added there later with evidence. |
| Assignment items | Opaque `(item_kind, item_id)` with no foreign key | The referenced tables do not exist until M6 and M7. A check constraint on known kinds would have to be widened by every later milestone. |
| Console scope | A Groups page; no assignments page | Groups are unusable without a way to write and test a rule. An assignments page would have nothing to assign until M6 brings scripts. |

## 3. Rule language

### Grammar

```
expr         := or
or           := and ( "OR" and )*
and          := not ( "AND" not )*
not          := "NOT" not | primary
primary      := "(" expr ")" | comparison | has_software
comparison   := field op literal
op           := "=" | "!=" | "<" | "<=" | ">" | ">=" | "LIKE"
has_software := "has_software" "(" string [ "," op "," string ] ")"
literal      := string | number
string       := "'" ... "'"    (doubled '' escapes a quote)
```

Keywords and field names are case-insensitive; string literals are not.

### Fields

| Field | Type | Source |
|---|---|---|
| `hostname` | string | `devices.hostname` |
| `os_version` | string | `devices.os_version` |
| `os_build` | string | `devices.os_build` |
| `manufacturer` | string | `devices.manufacturer` |
| `model` | string | `devices.model` |
| `serial` | string | `devices.serial` |
| `agent_version` | string | `devices.agent_version` |
| `ram_gb` | number | latest inventory |
| `last_seen_days` | number | whole days since `devices.last_seen_at` |

String fields accept `=`, `!=` and `LIKE`. Number fields accept the six
comparison operators but not `LIKE`. Using an operator a field does not accept
is a parse-time error naming the field and the operator, not a query that
quietly matches nothing.

### Limits

A rule is at most 2000 characters and 20 levels of nesting deep. Both are
rejected at parse time. Rules are written by administrators, not end users, so
the limits exist to turn a mistake into a clear error rather than a query that
takes the database down.

### Errors

A parse error reports the byte offset and what was expected, because the
console shows it under the rule editor while the administrator types.

## 4. Groups

A group is static or dynamic, and a built-in "All devices" group exists per
tenant.

- **Static:** membership is explicit; the API adds and removes devices.
- **Dynamic:** membership comes from the rule, and cannot be edited by hand.
- **Built-in:** "All devices" holds every active device and has no rule and no
  editable membership. It exists so that M6 can assign an item to the whole
  fleet without asking the administrator to build a group first.

Membership is materialized in `group_members`. It is recomputed:

- for one device, when its inventory changes, and when it enrolls;
- for every dynamic group, every 15 minutes, by a sweeper job using the
  framework M4 built;
- for one group, whenever its rule changes.

Recomputation is a single `INSERT ... SELECT` / `DELETE` pair inside a
transaction, so a group is never observed half-evaluated.

Deleting a group deletes its membership and its assignments.

## 5. Assignments

An assignment is `(item_kind, item_id, group_id, mode)`, where mode is
`include` or `exclude`.

A device's effective set is every item with at least one include assignment to
a group the device belongs to, and no exclude assignment to any group the
device belongs to. **Exclude always wins**, regardless of group, order, or how
specific the groups are. This is the one rule an administrator has to hold in
their head, so it has no exceptions.

The effective set is returned on check-in as a list of `{kind, id}`. Agents in
M5 have nothing to do with it yet; M6 gives the kinds meaning.

## 6. Item status

`device_item_status` records, per device and item, one of `pending`,
`succeeded`, `failed`, `conflict` or `not_applicable`, with a timestamp and a
detail string. M5 creates the table and the rollup queries; M6 and M7 write to
it as deployments and profiles report back.

Rollups count devices by status for an item, and drill down to the device list
for one status.

## 7. Data model

Migration `0004_groups_assignments`:

```sql
CREATE TABLE device_groups (
    id           uuid PRIMARY KEY,
    tenant_id    uuid NOT NULL REFERENCES tenants(id),
    name         text NOT NULL,
    description  text NOT NULL DEFAULT '',
    kind         text NOT NULL CHECK (kind IN ('static', 'dynamic', 'builtin')),
    rule         text NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL,
    updated_at   timestamptz NOT NULL,
    evaluated_at timestamptz
);
CREATE UNIQUE INDEX device_groups_name ON device_groups (tenant_id, lower(name));

-- A group is static or dynamic, never both, so a membership row needs no
-- column saying where it came from: the group's kind already says.
CREATE TABLE group_members (
    group_id  uuid NOT NULL REFERENCES device_groups(id) ON DELETE CASCADE,
    device_id uuid NOT NULL REFERENCES devices(id),
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    added_at  timestamptz NOT NULL,
    PRIMARY KEY (group_id, device_id)
);
CREATE INDEX group_members_device ON group_members (device_id);

-- item_id has no foreign key: the tables it points at arrive in M6 and M7.
CREATE TABLE assignments (
    id         uuid PRIMARY KEY,
    tenant_id  uuid NOT NULL REFERENCES tenants(id),
    item_kind  text NOT NULL,
    item_id    uuid NOT NULL,
    group_id   uuid NOT NULL REFERENCES device_groups(id) ON DELETE CASCADE,
    mode       text NOT NULL CHECK (mode IN ('include', 'exclude')),
    created_at timestamptz NOT NULL,
    created_by text NOT NULL
);
CREATE UNIQUE INDEX assignments_unique ON assignments (item_kind, item_id, group_id, mode);
CREATE INDEX assignments_group ON assignments (group_id);

CREATE TABLE device_item_status (
    device_id  uuid NOT NULL REFERENCES devices(id),
    tenant_id  uuid NOT NULL REFERENCES tenants(id),
    item_kind  text NOT NULL,
    item_id    uuid NOT NULL,
    status     text NOT NULL CHECK (status IN ('pending', 'succeeded', 'failed', 'conflict', 'not_applicable')),
    detail     text NOT NULL DEFAULT '',
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (device_id, item_kind, item_id)
);
CREATE INDEX device_item_status_item ON device_item_status (tenant_id, item_kind, item_id, status);
```

The migration also seeds the built-in group for the default tenant.

### Compiled rule shape

A rule compiles to the `WHERE` clause of:

```sql
SELECT d.id FROM devices d
LEFT JOIN device_inventory i ON i.device_id = d.id
WHERE d.tenant_id = $1 AND d.status = 'active' AND (<compiled rule>)
```

so `ram_gb` is `coalesce(i.ram_gb, 0)` and `last_seen_days` is
`floor(extract(epoch from ($2 - d.last_seen_at)) / 86400)`, with the clock
passed in rather than read as `now()` so tests are deterministic. A device that
has never checked in has a NULL `last_seen_at`, and so matches no
`last_seen_days` comparison.

`has_software('x')` becomes

```sql
EXISTS (SELECT 1 FROM device_software s
        WHERE s.device_id = d.id AND lower(s.name) = lower($n))
```

which uses the existing `device_software_name` index. With a version
comparison, ordering operators add

```sql
AND s.version ~ '^[0-9]+(\.[0-9]+)*$'
AND string_to_array(s.version, '.')::int[] <op> string_to_array($m, '.')::int[]
```

and `=` / `!=` compare `s.version` as text.

### Effective set

```sql
SELECT DISTINCT a.item_kind, a.item_id
FROM assignments a
JOIN group_members gm ON gm.group_id = a.group_id AND gm.device_id = $1
WHERE a.mode = 'include'
  AND NOT EXISTS (
      SELECT 1 FROM assignments x
      JOIN group_members gx ON gx.group_id = x.group_id AND gx.device_id = $1
      WHERE x.mode = 'exclude'
        AND x.item_kind = a.item_kind AND x.item_id = a.item_id)
```

## 8. Out of scope

An assignments console page, item kinds of any sort, and per-assignment options
such as schedules — those belong to the milestone that introduces the items
they configure.
