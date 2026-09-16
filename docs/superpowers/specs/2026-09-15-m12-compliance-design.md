# M12 — Compliance rules, overview dashboard, CSV export

Status: self-approved overnight under the user's standing directive ("please work on all of this while I go to bed"); every decision is listed in the overnight ledger for morning review. Builds on merged M1–M11.

## 1. What and why

An administrator can say what a healthy device looks like — BitLocker on, a minimum OS build, checked in recently, no forbidden software — assign that to groups, and see which devices meet it. This is the largest Intune capability Retune lacks, and it needs no new agent code: everything it evaluates is already reported by inventory, the device row, or the item-status table.

The same milestone adds the overview page an administrator lands on, and CSV export of devices and compliance results, because compliance is the first thing anyone wants to report on.

Out of scope: acting on non-compliance (conditional access, blocking), grace periods, per-rule severity, custom rule scripts. Firewall state is not collected by inventory and so is not a rule.

## 2. Model

- New item kind `compliance`. Policies are assigned to groups through the existing assignment engine (include/exclude, same effective-set logic). The agent never receives them: `agentapi.itemVersion` has no case for the kind, so check-in skips them.
- Table `compliance_policies(id uuid PK, tenant_id, name text, description text, rules jsonb, created_at, updated_at, created_by)`, `UNIQUE(tenant_id, name)`. No versions: a policy is edited in place and re-evaluated. Audit `compliance_policy.created|updated|deleted`.
- Table `device_compliance(device_id, policy_id, tenant_id, state text CHECK (state IN ('compliant','non_compliant','unknown')), failures jsonb NOT NULL DEFAULT '[]', evaluated_at timestamptz)`, PK `(device_id, policy_id)`, index on `(tenant_id, policy_id, state)`.
- A device's **overall** state is derived, not stored: `non_compliant` if any assigned policy is non-compliant, else `unknown` if any is unknown, else `compliant`; `not_evaluated` when no compliance policy applies.
- Every evaluation is also mirrored into `device_item_status` (kind `compliance`, version 1): compliant → `succeeded`, non_compliant → `failed`, unknown → `pending`, detail = the failures joined with "; ". That makes the existing `/items/compliance/{id}/status` rollup and its console component work unchanged.

## 3. Rules

A policy's `rules` is a JSON array of 1–50 objects, each `{"type": …, …params}`. Parsing is strict (unknown fields and unknown types rejected, bounds checked) and lives in `internal/server/compliance`.

| type | params | compliant when | unknown when |
|---|---|---|---|
| `os_build_min` | `build` (digits, dotted allowed) | device OS build ≥ `build`, compared segment-wise numerically | device has no OS build |
| `agent_version_min` | `version` (dotted numeric) | reported agent version ≥ `version` | version empty or not dotted-numeric (reported as failure detail, state unknown) |
| `bitlocker` | `volumes`: `system` \| `all` | `system`: the volume named `C:` is `on`; `all`: every fixed volume is `on` | no inventory, no volume to check (no system volume, or `all` with no fixed volumes reported), or a required volume reports `unknown` |
| `tpm` | `min_version` (optional, e.g. `2.0`) | TPM present and, if given, version ≥ `min_version` | no inventory, or a `min_version` to check against a TPM that reported no version |
| `checked_in_within` | `hours` 1–8760 | `last_seen_at` within `hours` | never seen |
| `inventory_within` | `hours` 1–8760 | inventory received within `hours` | never |
| `updates_within` | `days` 1–365 | last update installed within `days` | no inventory or no date reported |
| `no_pending_reboot` | — | inventory says no pending reboot | no inventory |
| `max_local_admins` | `count` 0–100 | number of local admins ≤ `count` | no inventory, or no local admins reported |
| `forbidden_software` | `name` (1–200 chars) | no installed package name contains `name` (case-insensitive) | no inventory, or no installed software reported |
| `required_software` | `name` | some installed package name contains `name` | no inventory, or no installed software reported |
| `profile_applied` | `profile_id` (uuid) | that profile's item status on the device is `succeeded` | no status row or `pending` |

Each failing or unknown rule produces a failure entry `{"rule": <type>, "state": "non_compliant"|"unknown", "detail": <one sentence a person can act on>}`, e.g. "BitLocker is off on C:", "last check-in was 9 days ago (limit 7)". Policy state: any non-compliant rule → non_compliant; else any unknown → unknown; else compliant.

The evaluator is a pure function over a `Facts` value (device row, parsed inventory and its received time, the device's profile statuses) and `now`; all rules are table-tested without a database.

## 4. When evaluation runs

- After every inventory ingest (beside the existing dynamic-group re-evaluation, same log-don't-fail rule).
- A sweeper job every 15 minutes evaluates every active device, so time-based rules (`checked_in_within`) catch devices that went silent.
- On demand: `POST /compliance-policies/{id}/evaluate` evaluates every device the policy currently applies to (the console's "Evaluate now").
- Evaluation of one device also deletes `device_compliance` and mirrored item-status rows for compliance policies that no longer apply to it.

## 5. Admin API

Read endpoints need any admin role, mutations need write.

- `GET/POST /compliance-policies`, `GET/POST/DELETE /compliance-policies/{id}` (POST on the id updates; DELETE removes assignments, results and mirrored statuses in one transaction), `POST /compliance-policies/{id}/evaluate`.
- `GET /compliance-policies/{id}/devices?state=` — paged device results with hostname, state, failures, evaluated_at.
- `GET /devices/{id}/compliance` — overall state plus each applicable policy's id, name, state and failures, ordered by policy name.
- `GET /devices` items gain `compliance` (overall state).
- `GET /dashboard` — `{devices:{active,stale,retired,total}, compliance:{compliant,non_compliant,unknown,not_evaluated}, failed_deployments:{script,app,profile,agent}, agent_versions:[{version,count}] (top 10), os_builds:[{build,count}] (top 10)}` for active devices.
- `GET /devices/export.csv` and `GET /compliance-policies/{id}/devices/export.csv` — `text/csv; charset=utf-8`, `Content-Disposition: attachment`, header row, one row per device. Any cell beginning with `=`, `+`, `-`, `@`, tab or carriage return is prefixed with `'` (spreadsheet formula injection). Device export columns: hostname, serial, manufacturer, model, os_version, os_build, agent_version, status, compliance, last_seen_at, enrolled_at.
- Assignment options for kind `compliance` must be empty (`{}` or absent).

## 6. Console

- **Overview** becomes the landing page (`/`): device fleet bar (the existing FleetBar), a compliance bar in the same visual language, failed deployments by kind linking to their pages, top agent versions and OS builds.
- **Compliance** page (nav after Profiles): list of policies with their rollup; editor dialog with one row per rule (type select, typed parameter inputs, remove), assign dialog (group + include/exclude), detail with the device results list filtered by state, "Evaluate now", "Export CSV".
- **Devices**: a compliance column and an "Export CSV" link. **Device detail**: a compliance section listing each policy with its failures.

## 7. Testing and verification

Pure rule tests per type (compliant, non-compliant, unknown, boundary); store tests; service tests (evaluation writes results and mirrors item status, unassigned policy rows removed, overall-state derivation); API tests (CRUD, roles, dashboard numbers, CSV content and formula guard); console tests; an e2e test that enrolls a device, uploads inventory with BitLocker off, assigns a BitLocker policy, and sees the device non-compliant, then uploads inventory with it on and sees it compliant.

On this machine only read-only verification: the policy evaluates the real inventory the agent reports; nothing on the machine changes.
