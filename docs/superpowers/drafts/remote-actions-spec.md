# M13 — Remote actions: lock, collect logs, local admin password rotation, wipe

Status: lock, collect_logs and wipe built in the remote-actions PR (see "As built"); password rotation is the next PR. Originally self-approved overnight under the user's standing directive; decisions ledgered for morning review. Builds on M1–M12. **Nothing in this milestone is ever executed against this machine** — lock, rotation and wipe are built and tested with fakes only.

## 1. What and why

Retune's only remote commands today are `run_powershell`, `restart` and `refresh_inventory`. Intune's day-to-day remote actions are missing: lock a lost machine, pull its logs, rotate the local administrator password (Windows LAPS's job), and wipe it. All four ride the existing command pipeline (queue → deliver at check-in → execute → result), so delivery, expiry, results and the Commands page are reused.

## 2. New command types

| type | payload | agent does |
|---|---|---|
| `lock` | none | runs `rundll32.exe user32.dll,LockWorkStation` in the active console session via `internal/agent/winsession`; with nobody signed in, succeeds with "nobody is signed in; there is nothing to lock" |
| `collect_logs` | `hours` 1–168 (default 24) | zips the agent's `logs/` directory, `update.json` if present, and the System and Application event logs for the last `hours` (via `wevtutil epl` with a time query) into one archive capped at 50 MiB, and uploads it (§3) |
| `rotate_local_admin_password` | `account` (optional; default the built-in administrator, RID 500, resolved on the device), `length` 20–64 (default 24) | generates a password from `crypto/rand` over an alphabet without look-alike characters; escrows it (§4) **before** setting it; sets it with `NetUserSetInfo` level 1003; reports |
| `wipe` | `protected` bool (default false) | invokes `MDM_RemoteWipe.doWipeMethod` (or `doWipeProtectedMethod` when protected) in `root\cimv2\mdm\dmmap` as SYSTEM, after first reporting the result `succeeded` with detail "wipe started" (nothing can report afterwards) |

All four go through `commands.Service.Queue` validation (typed payload parsing, unknown fields rejected) and the agent executor's switch. Each Windows side effect sits behind a small interface (`Locker`, `LogCollector`, `PasswordSetter`, `Wiper`) with a fake for tests and an `_other.go` stub returning "not supported on this platform".

## 3. Log upload

- Agent endpoint `POST /api/agent/v1/commands/{id}/artifact` — raw octet-stream body, ≤ 50 MiB (`MaxBytesReader`), accepted only when the command belongs to the calling device, is of type `collect_logs`, and is `running`; one artifact per command (a second upload is 409).
- Stored under `DATA_DIR/command-artifacts/<command-id>.zip`, with its SHA-256 and size recorded in a new table `command_artifacts(command_id PK, tenant_id, size_bytes, sha256, created_at)`.
- Admin `GET /commands/{id}/artifact` streams it (`application/zip`, attachment), audited `command.artifact_downloaded`.
- Sweeper job deletes artifacts (row and file) older than 30 days.

## 4. Local admin passwords

- Table `local_admin_passwords(id uuid PK, tenant_id, device_id, account text, sealed bytea, state text CHECK (state IN ('pending','active','superseded','abandoned')), command_id uuid, created_at, activated_at)`.
- Sealing uses the same `secrets.Key.Seal`/`Open` the BitLocker escrow uses (AES-GCM with the server secret key), with additional data `"<device-id>/<ACCOUNT>"` so a row copied to another device or account does not decrypt — the same shape as `bitlocker.escrowContext`. Columns `ciphertext bytea, nonce bytea` as in `bitlocker_keys`.
- Agent endpoint `POST /api/agent/v1/admin-passwords` `{command_id, account, password}` → stored `pending`. The agent sets the password only after this returns 2xx: a password set but never escrowed is a lockout.
- When the `rotate_local_admin_password` command's result arrives `succeeded`, the pending row for that command becomes `active` and any earlier `active` row for the same device and account becomes `superseded`, in one transaction. A `failed` or `timed_out` result marks it `abandoned`.
- Admin `GET /devices/{id}/admin-passwords` lists metadata (account, state, dates — never the secret); `POST /admin-passwords/{id}/reveal` with a required `reason` returns the password and is audited `local_admin_password.revealed` (refused if the audit write fails, as BitLocker does). Only `active` and `superseded` rows can be revealed.

## 5. Wipe guardrails

- Queueing a `wipe` requires the admin role (the role model has only `admin` and `read_only`, so the existing `write` gate is exactly that), a `confirm_hostname` equal to the device's current hostname (case-insensitive), and a non-empty `reason`. Audit `command.wipe_queued` carries the reason.
- A wipe command's delivery expiry is 24 hours: a lost device that comes back online a week later does not wipe itself on an order nobody remembers.
- The console's wipe dialog makes the administrator type the hostname and a reason; the button stays disabled until the hostname matches.

## 6. Console

- Device detail gains an **Actions** menu: Lock, Collect logs, Rotate admin password, Wipe — each opening a small dialog, queueing the command, and linking to it on the Commands page.
- Commands page: the new types render their payloads; a finished `collect_logs` command shows a Download link.
- Device detail gains a **Local admin password** section (list + reveal-with-reason), modelled on the recovery keys section.

## 7. Testing

Executor tests with fakes for each type (including: nobody signed in for lock; escrow failure means the password is never set; wipe reports before invoking). Server tests: payload validation, wipe guardrails (hostname mismatch, missing reason, read-only role), artifact upload gating (wrong device, wrong type, not running, too large, duplicate), password state machine (success → active + supersede; failure → abandoned), reveal audit and refusal when auditing fails, artifact retention sweep. An e2e test drives `collect_logs` and `rotate_local_admin_password` through the real server with a fake agent client. Console tests for each dialog.

No on-machine verification of lock, rotation or wipe. `collect_logs` is read-only and may be verified against the installed agent if an agent is installed for another reason.

## As built (lock, collect_logs, wipe)

- **Split.** Password rotation (§4) is its own backlog item, 5b.
- **Wipe reports after Windows accepts it, not before.** `MDM_RemoteWipe.doWipeMethod` returns once the reset is scheduled. Reporting first would claim a wipe that might then fail, so the agent reports "wipe started" only after the call succeeds, and a refusal is reported as failed. The reset can still overtake the report.
- **Wipe from the admin API** also refuses API tokens (403) and requests naming more than one device. The server CLI can wipe with `--confirm-hostname` and `--reason`.
- **Lock** runs `rundll32 user32.dll,LockWorkStation` through `winsession.RunPowerShell` as the signed-in user; no new session helper was needed.
- **collect_logs** fits the archive under 50 MiB by leaving out whatever wouldn't fit and listing it in the result, rather than failing. The artifact download needs the admin role (`write`), not `read`: event logs are sensitive.
- **Retention.** The `command_artifacts` rows cascade from `commands`, so command retention removes them. The `commands.prune_artifacts` sweeper job (hourly) deletes files older than 30 days and any file without a row.
