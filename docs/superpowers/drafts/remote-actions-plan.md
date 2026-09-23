# M13 Remote Actions Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Lock, collect logs, rotate the local administrator password, and wipe — as command types through the existing command pipeline.

**Architecture:** New command types in `internal/protocol/commands.go`, validated in `internal/server/commands`, executed by `internal/agent/executor` behind per-action interfaces with Windows implementations and fakes. Two new agent endpoints (log artifact upload, admin password escrow), one new admin download, one reveal. Migration 0012.

**Tech Stack:** Go 1.27 (`golang.org/x/sys/windows` already a dependency), pgx/v5, React 19 + vitest.

**Spec:** `docs/superpowers/specs/2026-09-15-m13-remote-actions-design.md`

## Global Constraints

- Command type strings: `lock`, `collect_logs`, `rotate_local_admin_password`, `wipe`.
- `collect_logs.hours` 1–168 default 24; archive cap 50 MiB; artifact retention 30 days.
- `rotate_local_admin_password.length` 20–64 default 24; alphabet excludes `0 O o 1 l I |` and quotes; `crypto/rand` only.
- Escrow before set. Password states: `pending`, `active`, `superseded`, `abandoned`; only `active`/`superseded` revealable; reveal requires a reason and is refused if its audit write fails.
- Wipe: `confirm_hostname` must equal the device hostname case-insensitively, `reason` required, TTL 24h, audit `command.wipe_queued`; agent reports `succeeded` "wipe started" before invoking.
- **Never execute lock, rotation or wipe on this machine.** Windows side effects live behind interfaces; tests use fakes. Tests must not call the real implementations (guard: the Windows implementations are only constructed in `runner`/`cmd` wiring, never in tests).
- Every single-row store query takes `tenantID` after `ctx` (M11 convention).
- No new Go dependencies. Do not install, start, stop or touch any Windows service. Do not run `go test ./...` inside a task.
- Go comments are prose explaining why. Commits conventional, ending with a blank line and `Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>`.

---

### Task 1: Protocol, server validation, wipe guardrails

**Files:** `internal/protocol/commands.go` (types + payload structs `CollectLogsPayload{Hours}`, `RotateAdminPasswordPayload{Account string; Length int}`, `WipePayload{Protected bool}`), `internal/server/commands/service.go` (validation in the existing switch; `QueueOptions` gains `ConfirmHostname`, `Reason`; wipe: hostname match against the device row, reason required, TTL forced to 24h, extra audit `command.wipe_queued` with reason), `internal/server/adminapi` command handler (pass the two new fields from the request body). Tests: `internal/server/commands/service_test.go`, app-level test for the wipe guardrails over HTTP (mismatch 400, missing reason 400, read-only 403, success 201 and the audit row).

- [ ] TDD; commit `feat(commands): lock, log collection, password rotation and wipe command types`.

### Task 2: Store and migration

**Files:** `internal/server/store/migrations/0012_remote_actions.{up,down}.sql` (`command_artifacts`, `local_admin_passwords` per spec §3–4), `internal/server/store/remoteactions.go` + tests.

**Produces:** `CreateCommandArtifact`, `GetCommandArtifact(ctx, tenantID, commandID)`, `DeleteCommandArtifactsBefore(ctx, cutoff) ([]uuid.UUID, error)` (returns deleted ids so files can be removed); `CreateAdminPassword` (pending), `ActivateAdminPassword(ctx, tenantID, commandID, now)` (pending→active and supersede the previous active for the same device+account, one statement or transaction), `AbandonAdminPassword(ctx, tenantID, commandID)`, `ListAdminPasswords(ctx, tenantID, deviceID)` (metadata only), `GetAdminPassword(ctx, tenantID, id)`.

- [ ] TDD incl. tenant scoping and the supersede logic; commit `feat(store): command artifacts and escrowed local admin passwords`.

### Task 3: Server services and endpoints

**Files:** new `internal/server/remoteactions/` package (`Artifacts` service: store bytes under `DATA_DIR/command-artifacts`, reuse `artifacts.Store`-style `.part`+rename+size cap; `Passwords` service: escrow with `secrets.Key.Seal` and AAD `"<device-id>/<ACCOUNT>"`, reveal with audit), hook into `commands.Service.Complete` so a rotate command's result activates or abandons its password (an interface on `commands.Service`, like `inventory.Membership`), agent endpoints `POST /api/agent/v1/commands/{id}/artifact` and `POST /api/agent/v1/admin-passwords`, admin endpoints `GET /commands/{id}/artifact`, `GET /devices/{id}/admin-passwords`, `POST /admin-passwords/{id}/reveal`, sweeper job for artifact retention (new unique LockID), app wiring.

- [ ] Tests (app package, testcontainers): artifact upload gating (wrong device 404, wrong type 409, not running 409, >50 MiB 413, duplicate 409, success then download with audit); password escrow → result succeeded → active, earlier active → superseded; result failed → abandoned; reveal returns plaintext only for active/superseded and audits; reveal refused when the audit insert fails (inject a failing audit via a test hook or a closed transaction, whichever the codebase's BitLocker reveal test uses); retention sweep removes file and row. Commit `feat(server): log artifacts and local admin password escrow`.

### Task 4: Agent executor

**Files:** `internal/agent/executor/executor.go` (new cases), new `internal/agent/executor/actions.go` (interfaces `Locker{Lock(ctx) (string, error)}`, `LogCollector{Collect(ctx, hours int, dst io.Writer) error}`, `PasswordSetter{DefaultAdmin() (string, error); SetPassword(account, password string) error}`, `Wiper{Wipe(ctx, protected bool) error}`), `actions_windows.go` (real: `winsession.RunPowerShell` or a direct `rundll32` launch in the user session for lock; `wevtutil epl` + zip for logs; `NetUserSetInfo` level 1003 via `golang.org/x/sys/windows` syscall and `LookupAccountSid` on the RID-500 SID for the default account; `MDM_RemoteWipe` via PowerShell `Invoke-CimMethod -Namespace root\cimv2\mdm\dmmap -ClassName MDM_RemoteWipe -MethodName doWipeMethod|doWipeProtectedMethod` for wipe), `actions_other.go` (stubs), agent client methods `UploadCommandArtifact(ctx, id, r io.Reader)` and `EscrowAdminPassword(ctx, commandID, account, password)` in `internal/agent/client/client.go`, `internal/agent/runner/runner.go` wiring.

- [ ] Tests with fakes only: lock with nobody signed in succeeds with the stated detail; collect uploads exactly what the collector wrote and fails cleanly over 50 MiB; rotation escrows before setting and never sets when escrow fails, password length and alphabet honoured; wipe reports "wipe started" before calling the wiper, and a wiper error after that is logged (nothing left to report to). A test asserts the exact PowerShell/command lines the Windows implementations build, by exposing the line builders as pure functions — without running them. Commit `feat(agent): execute lock, log collection, password rotation and wipe`.

### Task 5: Console

**Files:** `web/src/pages/DeviceDetail.tsx` (Actions menu + four dialogs; wipe dialog with typed hostname and reason, button disabled until match), `web/src/components/AdminPasswords.tsx` (+test, modelled on `RecoveryKeys.tsx`), `web/src/pages/Commands.tsx` (new types' payload rendering; Download link for a finished `collect_logs`), `web/src/api/types.ts`.

- [ ] Tests per dialog (sends the right command body; wipe disabled until hostname matches; reveal requires a reason). `npx vitest run`, `npx tsc --noEmit -p .`. Commit `feat(console): remote actions and local admin passwords`.

### Task 6: End to end, docs

**Files:** `test/e2e/e2e_test.go` (`TestRemoteActionsEndToEnd`: queue collect_logs → deliver → start → upload artifact → complete → admin downloads identical bytes; queue rotate → escrow → complete succeeded → reveal returns the escrowed password; wipe with wrong hostname refused), `README.md` ("Remote actions" section), roadmap (M13 row; status line).

- [ ] Commit `test(e2e): remote actions end to end` and `docs: remote actions`.
