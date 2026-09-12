# Retune — Core Platform Design (Sub-project 1)

**Date:** 2026-09-12
**Status:** Draft for review

## 1. Summary

Retune is a self-hostable endpoint management system (similar in spirit to Microsoft Intune). A single server codebase runs either **on-prem** (Docker Compose or native service) or in the **cloud** (container behind a load balancer with managed Postgres). A Go agent runs on Windows endpoints, enrolls with a token, checks in over mTLS, reports inventory, runs commands and scripts, and enforces configuration profiles.

This spec covers sub-project 1: core platform + device groups + script deployments + configuration profiles.

### Roadmap (future specs)

1. **Core platform, groups, scripts, config profiles (this spec)**
2. App deployment (MSI/EXE packages, content store, install/uninstall with reporting)
3. Compliance rules and reporting
4. Native Windows MDM channel (MS-MDE2 enrollment + OMA-DM/SyncML), surfaced as a `csp` setting handler inside profiles
5. macOS and Linux agents
6. Agent self-update, SSO (OIDC/Entra ID), multi-tenancy UI, push hints (long-poll/WebSocket)

### Decisions

| Topic | Decision |
|---|---|
| Deployment | One server binary; on-prem vs cloud differs only by config |
| Endpoint OS | Windows first; OS-specific code behind interfaces |
| Management channel | Custom agent now; native Windows MDM added later (hybrid) |
| Tenancy | Single-tenant; every table carries `tenant_id` (default tenant) |
| Stack | Go server + Go agent, PostgreSQL everywhere, React + TypeScript console embedded in server |
| Transport | Agent polls server over HTTPS; mTLS after enrollment; no inbound connections to endpoints |

### Out of scope for this spec

App deployment, compliance rules, native MDM protocol, SSO, multi-tenancy UI, agent self-update, macOS/Linux, signed command payloads, TPM-backed keys.

## 2. Architecture

```
┌──────────────┐   HTTPS (mTLS)   ┌────────────────────────────┐
│ retune-agent │ ───────────────▶ │ retune-server (Go)         │
│ Windows svc  │   poll/check-in  │  ├ agent API  (mTLS)       │
└──────────────┘                  │  ├ admin API  (session)    │
                                  │  ├ web console (go:embed)  │
                                  │  ├ internal CA             │
                                  │  ├ command/assignment eng. │
                                  │  └ background sweepers     │
                                  └────────────┬───────────────┘
                                               ▼
                                          PostgreSQL
```

- The server is stateless (all state in Postgres) so it can run as multiple replicas in the cloud.
- Background jobs (command expiry, stale-device flagging, dynamic group evaluation) use Postgres advisory locks so only one replica runs each job at a time.

### On-prem vs cloud

| Concern | On-prem | Cloud |
|---|---|---|
| Packaging | `docker-compose.yml` (server + Postgres) or native Windows/Linux service | Container image (ECS, Azure Container Apps, Kubernetes, …) |
| Database | Bundled Postgres | Managed Postgres |
| TLS | `self-signed` or `provided` cert | `provided` or `behind-proxy` (LB terminates TLS; mTLS client cert passed via trusted header or TLS passthrough) |
| CA key | File on disk (`KeyStore` = file) | `KeyStore` = env/secret manager; KMS implementation later |

Config precedence: environment variables > `retune-server.yaml` > defaults. Key settings: `DATABASE_URL`, `PUBLIC_URL`, `TLS_MODE` (`self-signed` | `provided` | `behind-proxy`), `TLS_CERT_FILE`, `TLS_KEY_FILE`, `CA_KEY_SOURCE`, `AGENT_API_LISTEN`, `ADMIN_API_LISTEN`.

In `behind-proxy` mode the agent API requires TLS passthrough or a trusted proxy header carrying the verified client cert; the server refuses to start in `behind-proxy` without one of these configured.

## 3. Enrollment and security

### Enrollment tokens

- Created by an admin with optional label, expiry, and max uses.
- Displayed once; only a SHA-256 hash is stored. Revocable.
- Install: `msiexec /i retune-agent.msi SERVER_URL=https://mdm.example.com ENROLL_TOKEN=xxxx [SERVER_CERT_FINGERPRINT=sha256:...] /qn`

### Enrollment flow

1. Agent generates an ECDSA P-256 keypair. Private key is protected with DPAPI (machine scope) behind a `KeyProvider` interface (TPM implementation later).
2. Agent calls `POST /api/agent/v1/enroll` (server-auth TLS only) with token, CSR, hostname, serial, SMBIOS UUID, OS version.
3. Server validates token (not expired, not revoked, uses remaining) and, **in one transaction**, increments use count, creates the device, and issues a client cert signed by the internal CA (90-day validity, subject CN = device ID).
4. Server returns device ID, client cert, CA chain.
5. Agent stores identity in `C:\ProgramData\Retune\` with ACLs restricted to SYSTEM and Administrators.
6. All further agent calls use mTLS; the server identifies the device by cert and checks the device status in the DB on every request.

### Server trust

- `SERVER_CERT_FINGERPRINT` given: agent requires a certificate in the server's presented chain with that SHA-256 fingerprint and verifies the leaf against it. In `self-signed` mode this is the internal CA's fingerprint (`retune-server ca fingerprint`), so server leaf rotation does not break pinning.
- Otherwise: system trust store validation. (No trust-on-first-use.)

### Certificate lifecycle

- Agent renews when fewer than 30 days remain: `POST /api/agent/v1/renew` with a new CSR over the existing mTLS connection.
- Revocation: admin retires device → status `retired` → server rejects requests with `401`. No CRL/OCSP in v1.
- Re-enrollment of a reimaged machine (matching serial or SMBIOS UUID): old device marked `replaced`; new device inherits name and static group memberships.

### Admin authentication

- Local accounts, Argon2id password hashes, session cookies (HttpOnly, Secure, SameSite=Strict), CSRF tokens on state-changing requests.
- Optional TOTP MFA per admin.
- `Authenticator` interface so OIDC can be added later.
- Roles in v1: `admin` (full access) and `read_only`.
- First admin created via `retune-server bootstrap-admin --email ...` CLI command.

### Audit log

Every admin action is recorded: token created/revoked, command issued, device retired, script/profile created/edited/assigned, BitLocker key viewed, admin created, login success/failure.

### Command/script execution security

- Only authenticated `admin` role can queue commands or create/assign scripts and profiles.
- Scripts run with a timeout and 1 MB stdout/stderr cap.

## 4. Check-in protocol

### Agent loop

- Interval: 5 minutes ± 20% jitter; server may override interval in the check-in response.
- `POST /api/agent/v1/checkin` request: agent version, uptime, logged-in user, IP addresses, last inventory hash, local state summary (hash of applied items).
- Response:
  - `interval_seconds`
  - `inventory_due` (bool)
  - `commands`: pending ad-hoc commands
  - `items`: effective set of assigned scripts and profiles as `[{kind, item_id, version, hash}]`
- Agent fetches changed items via `GET /api/agent/v1/items/{kind}/{id}/versions/{version}`.
- On network failure: exponential backoff up to 30 minutes; results are queued in a local store (`C:\ProgramData\Retune\state.db`, BoltDB/bbolt) and flushed on reconnect.

### Error classes (agent-facing)

- **Retryable:** network errors, 5xx, 429 → backoff.
- **Fatal:** `401` (cert revoked/retired) → stop check-ins, log to Event Log, idle with daily retry. `410` (unenrolled) → wipe identity and uninstall.

## 5. Inventory

- Full collection at enrollment, every 24 hours, and on `refresh_inventory` command.
- `PUT /api/agent/v1/inventory` with a JSON document; skipped if the content hash matches the last accepted hash.
- Windows collector (`InventoryCollector` interface):
  - OS: edition, version, build, install date, last boot
  - Hardware: manufacturer, model, serial, CPU, RAM, disks (size/free), BitLocker status per volume, TPM presence/version
  - Network adapters: name, MAC, IPs
  - Installed software: Uninstall registry keys (64-bit, 32-bit WOW6432Node, per-user hives)
  - Local users and local Administrators members
  - Pending reboot flag, Windows Update last successful install date
- Server stores the full document as JSONB plus extracted columns for filtering and a normalized `device_software` table.

## 6. Ad-hoc commands

- Types: `run_powershell` (script, timeout, run_as), `restart` (delay, message), `refresh_inventory`, `unenroll`.
- States: `queued → delivered → running → succeeded | failed | timed_out | expired`.
- TTL default 7 days; the sweeper expires undelivered commands.
- Result: `POST /api/agent/v1/commands/{id}/result` with exit code, stdout, stderr (each capped at 1 MB), started/finished timestamps.
- Idempotency: agent records completed command IDs in its local store and never re-executes one.
- Bulk: console can queue one command to many devices (one command row per device).

## 7. Device groups

- **Static groups:** explicit membership.
- **Dynamic groups:** membership defined by a rule expression over device and inventory fields.
  - Grammar: comparisons (`=`, `!=`, `<`, `<=`, `>`, `>=`, `LIKE`), `AND`, `OR`, `NOT`, parentheses, and function `has_software(name[, version_op, version])`.
  - Fields: `hostname`, `os_version`, `os_build`, `manufacturer`, `model`, `serial`, `ram_gb`, `agent_version`, `last_seen_days`.
  - The rule is parsed into an AST and compiled to parameterized SQL (never string-concatenated).
  - Evaluated on inventory change for that device and every 15 minutes for all dynamic groups.
- Built-in group "All devices".
- A device may be in many groups.

## 8. Assignments

- `assignment` = (item kind, item id, group id, mode `include` | `exclude`, options).
- Effective set per device: items with at least one include-assignment matching one of its groups and no exclude-assignment matching any of its groups. Exclude always wins.
- Effective set is computed on check-in (cached per device, invalidated on membership/assignment/item changes).
- Per-device item status in `device_item_status`: `pending | succeeded | failed | conflict | not_applicable`, with last-updated timestamp and detail.
- Console rollups per item: counts by status, drill-down to device list.

## 9. Script deployments

- Script library: name, description, PowerShell body. Every edit creates a new immutable version.
- Assignment options:
  - `frequency`: `once` | `recurring` (interval hours/days)
  - `run_as`: `system` | `logged_in_user` (skipped with `pending` status if no user is logged in)
  - `timeout_seconds`, `max_retries`
  - `rerun_on_new_version` (bool)
- Optional detection + remediation pair: detection runs first; remediation runs only when detection exits non-zero; detection runs again afterwards and its exit code determines success.
- Agent `scripts` package schedules runs based on local state (last run time and version per script) and reports each run to `POST /api/agent/v1/scripts/{id}/runs`.
- Results stored in `script_runs` with the same caps as command results.

## 10. Configuration profiles

- A profile is a named, versioned set of settings. Each edit creates a new immutable version.
- The agent `policy` package reconciles on every check-in: for each setting in every effective profile, call handler `Test`; if non-compliant, call `Set`; then `Test` again and report.
- Per-setting status: `compliant | remediated | error | conflict`.
- `SettingHandler` interface: `Kind() string`, `Get(ctx, spec) (State, error)`, `Test(ctx, spec) (bool, error)`, `Set(ctx, spec) error`, optional `Revert(ctx, spec) error`.

### v1 setting types

| Kind | Spec | Notes |
|---|---|---|
| `registry` | hive (`HKLM`/`HKCU`), key, value name, type (`REG_SZ`, `REG_DWORD`, `REG_QWORD`, `REG_MULTI_SZ`, `REG_EXPAND_SZ`), data, or `ensure: absent` | `HKCU` applied to logged-in user's loaded hive |
| `service` | name, startup type, desired state (`running`/`stopped`) | |
| `local_group_members` | group name, members, mode (`additive`/`exact`) | `exact` never removes the built-in Administrator account |
| `firewall` | per-profile enabled flag; named inbound/outbound rules (port, protocol, program, action) | Rules created by Retune are tagged in their group name `Retune` so they can be managed/removed |
| `windows_update` | deferral days (quality/feature), active hours, auto-restart behavior | Implemented via WindowsUpdate policy registry keys |
| `bitlocker` | require OS drive encryption, encryption method, escrow recovery key | Recovery key uploaded to `bitlocker_keys` (encrypted at rest with a server key via `KeyStore`); viewing is audited |
| `file` | path, content (base64), sha256, `ensure: present/absent` | Max 1 MB per file |

### Setting identity and conflicts

- Each setting has an identity key (e.g. `registry:HKLM\Software\X\ValueName`, `service:Spooler`).
- If two effective profiles set the same identity key to different values, the agent applies neither and reports `conflict` for both; the console highlights the conflict with both profile names.
- Identical values from different profiles are not a conflict.

### Removal

- When a profile leaves a device's effective set, the agent stops enforcing its settings.
- If the profile has `revert_on_removal` enabled and the handler implements `Revert`, the agent restores the value it recorded before first applying the setting (stored in local state).

## 11. Data model

All tables include `tenant_id` (FK to `tenants`, default single tenant). Timestamps are `timestamptz`. IDs are UUIDv7.

- `tenants`: id, name
- `admins`: id, email, password_hash, totp_secret (encrypted), role, created_at, last_login_at
- `sessions`: id, admin_id, expires_at, csrf_token
- `enrollment_tokens`: id, token_hash, label, expires_at, max_uses, use_count, revoked_at, created_by
- `devices`: id, hostname, serial, smbios_uuid, os_version, os_build, manufacturer, model, status (`active`/`retired`/`replaced`), cert_serial, cert_expires_at, last_seen_at, agent_version, enrolled_at, replaced_by
- `device_inventory`: device_id, collected_at, hash, data (JSONB), ram_gb, disk_free_gb
- `device_software`: device_id, name, version, publisher, install_date
- `commands`: id, device_id, type, payload (JSONB), status, created_by, created_at, delivered_at, completed_at, expires_at
- `command_results`: command_id, exit_code, stdout, stderr, started_at, finished_at
- `groups`: id, name, kind (`static`/`dynamic`/`builtin`), rule (text), rule_ast (JSONB)
- `group_members`: group_id, device_id, source (`static`/`dynamic`)
- `scripts`: id, name, description, current_version
- `script_versions`: script_id, version, body, detection_body, hash, created_by, created_at
- `profiles`: id, name, description, current_version, revert_on_removal
- `profile_versions`: profile_id, version, settings (JSONB), hash, created_by, created_at
- `assignments`: id, item_kind, item_id, group_id, mode, options (JSONB), created_by
- `device_item_status`: device_id, item_kind, item_id, version, status, detail (JSONB), updated_at
- `script_runs`: id, device_id, script_id, version, phase (`detection`/`remediation`/`run`), exit_code, stdout, stderr, started_at, finished_at
- `bitlocker_keys`: device_id, volume_id, key_ciphertext, created_at
- `audit_log`: id, actor, action, target_kind, target_id, details (JSONB), at

Migrations: `golang-migrate`, embedded in the binary, run at startup (with advisory lock).

## 12. Admin console (React + TypeScript, Vite, embedded via `go:embed`)

- Login (+ TOTP)
- Devices: list (search, filter by status/OS/group/last seen, stale badge >7 days), detail (overview, inventory tabs, software, groups, assigned items and per-setting status, command history, script runs), actions (run command, retire)
- Bulk actions on selected devices
- Groups: list, static membership editor, dynamic rule builder with live "matching devices" preview
- Scripts: library, editor with versions, detection/remediation pair, assignments, status rollup
- Profiles: list, editor (form per setting type), versions, assignments, status rollup, conflict view
- Enrollment tokens: create (show once), list, revoke
- Audit log
- Admin users (create, role, reset MFA)

## 13. Repository layout

```
retune/
├ cmd/
│  ├ retune-server/        server main + CLI (serve, migrate, bootstrap-admin)
│  └ retune-agent/         agent main (install, run, uninstall service)
├ internal/
│  ├ server/
│  │  ├ agentapi/          mTLS agent endpoints
│  │  ├ adminapi/          console REST API
│  │  ├ auth/              Authenticator iface, local accounts, sessions, TOTP
│  │  ├ ca/                internal CA, KeyStore iface
│  │  ├ enroll/            token validation, device creation, cert issue/renew
│  │  ├ commands/          ad-hoc command queue and lifecycle
│  │  ├ inventory/         ingest, hash compare, software normalization
│  │  ├ groups/            static/dynamic groups, rule parser + SQL compiler
│  │  ├ assignments/       effective-set computation, status rollups
│  │  ├ scripts/           library, versions
│  │  ├ profiles/          profile model, setting schema validation, conflict detection
│  │  ├ sweeper/           background jobs with advisory locks
│  │  ├ audit/
│  │  └ store/             Postgres repository layer + embedded migrations
│  ├ agent/
│  │  ├ client/            HTTP/mTLS client, backoff, offline result queue
│  │  ├ identity/          KeyProvider iface, DPAPI impl, cert storage
│  │  ├ state/             bbolt local store
│  │  ├ checkin/           loop, jitter, dispatch
│  │  ├ executor/          ad-hoc command handlers
│  │  ├ scripts/           script scheduler and runner
│  │  ├ policy/            reconcile loop, SettingHandler registry, handlers/
│  │  └ inventory/         InventoryCollector iface + windows impl
│  ├ protocol/             shared v1 request/response types
│  └ config/               server and agent configuration
├ web/                     React + TS console
├ deploy/
│  ├ docker/               Dockerfile, docker-compose.yml
│  └ msi/                  WiX sources for agent MSI
└ docs/
```

## 14. Error handling

- Agent: every loop iteration recovers from panics, logs, and backs off; the service never exits on errors. Logs go to the Windows Event Log (source `Retune`) and a rotating file under `C:\ProgramData\Retune\logs`.
- Server: structured JSON errors `{code, message}`; request IDs in logs and responses; structured logging via `log/slog`.
- Enrollment, assignment changes, and item version creation are transactional.
- Setting handler errors are isolated per setting; one failing setting does not stop the rest of the profile.

## 15. Testing

- Unit tests per package with fakes for store, KeyStore, collectors, and setting handlers.
- TDD for core logic: token validation, command state machine, cert renewal decision, rule parser/compiler, effective-set computation, conflict detection, script scheduling.
- Store tests against real Postgres via `testcontainers-go`.
- End-to-end test: server + Postgres + agent in test mode (fake collector, fake setting handlers, temp identity dir), covering enroll → check-in → inventory → dynamic group match → script deployment → profile apply/drift/remediate → ad-hoc command → retire.
- Windows-specific handlers and collector tested behind `//go:build windows` in a Windows CI job.
- Web console: component tests (Vitest + Testing Library) for the rule builder and profile editor forms.

## 16. Packaging

- Server: multi-stage Docker image (distroless), plus Linux and Windows binaries.
- `deploy/docker/docker-compose.yml`: server + Postgres with volumes for DB and CA key.
- Agent: MSI (WiX) installs `retune-agent.exe` as an auto-start LocalSystem service; accepts `SERVER_URL`, `ENROLL_TOKEN`, `SERVER_CERT_FINGERPRINT`.
