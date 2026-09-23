# M19 Uploaded Application Packages Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Deploy uploaded MSI/EXE packages through M9's `app` item kind with detection rules and supersedence.

**Architecture:** App `source` (`winget`|`package`); package versions with an uploaded file (M10 artifact pattern, ≤ 2 GiB), installer metadata and one detection rule; agent `apps.Syncer` gains a package path with a hash-verified download cache and a fake-able installer runner.

**Tech Stack:** Go 1.27, pgx/v5, React 19 + vitest.

**Spec:** `docs/superpowers/specs/2026-09-15-m19-app-packages-design.md`

## Global Constraints

- Fields, defaults and detection rules exactly as spec §2–3. Success exit codes default `0,3010,1641`; 3010/1641 → succeeded "installed; a restart is required to finish".
- **No installer is ever executed during implementation or overnight verification.** The installer runner, registry reader and file-version reader are interfaces; tests use fakes.
- Download verified against the recorded SHA-256 before running (M10 `DownloadAgentBinary` pattern).
- Every single-row store query takes `tenantID` after `ctx`. No new Go dependencies. Do not touch any Windows service. Do not run `go test ./...` inside a task.
- Go comments are prose explaining why. Commits conventional, ending with a blank line and `Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>`.

---

### Task 1: Protocol, migration, store

**Files:** `internal/protocol/app.go` (package definition, detection rule types + validation), migration (apps.source, package version columns, supersedes), store methods + tests.

- [ ] Commit `feat(store): uploaded application packages`.

### Task 2: Server

**Files:** `internal/server/apps` (package version upload with `MaxBytesReader` 2 GiB, `.part`+hash+rename under `DATA_DIR/app-packages`), admin upload endpoint, agent definition carries package metadata, agent download endpoint gated on `DeviceHasItem`; tests.

- [ ] Commit `feat(server): upload and serve application packages`.

### Task 3: Agent

**Files:** `internal/agent/apps` (package path in the syncer; `detect.go` pure rule evaluation over `RegistryReader`/`FileReader` interfaces; `installer.go` interface + Windows implementation running `msiexec` / the EXE with arguments and timeout; cache under `DATA_DIR/app-cache` pruned when a version is no longer assigned); client download method; tests with fakes (install when missing, skip when detected, uninstall, supersede with/without uninstall_previous, hash mismatch, timeout, reboot-required mapping).

- [ ] Commit `feat(agent): install uploaded packages with detection rules`.

### Task 4: Console, e2e, docs

**Files:** Apps page "Add app" source choice, package form (upload, type, args, exit codes, timeout, detection rule builder, supersedes select); e2e (`TestAppPackageEndToEnd`: upload, assign, fake agent client fetches definition and hash-verified bytes, reports result); `README.md`; roadmap (M19 row).

- [ ] Commit `feat(console): application packages`, `test(e2e): application packages`, `docs: uploaded application packages`.
