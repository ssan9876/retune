# M18 Signed Command Payloads Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Let an agent build require Ed25519 signatures from an offline operations key on `run_powershell`, script versions and `wipe` orders.

**Architecture:** Two new manifest types in `internal/release`; `retune-sign sign-script` / `sign-command`; `facts.OperationsKeysRaw` embedded at build time; agent-side verification in the executor and the script scheduler; server-side early rejection and a new `awaiting_signature` command state for wipe.

**Tech Stack:** Go 1.27 stdlib (`crypto/ed25519`), pgx/v5, React 19 + vitest.

**Spec:** `docs/superpowers/specs/2026-09-15-m18-signed-commands-design.md`

## Global Constraints

- Script manifest: `retune-script-manifest/v1\nsha256=<lowercase hex of the exact script bytes>\n`.
- Wipe manifest: `retune-command-manifest/v1\ntype=wipe\ndevice=<id>\ncommand=<id>\nprotected=<true|false>\nexpires=<RFC3339 UTC>\n`; expiry ≤ 24 h after signing.
- Enforcement only when `facts.OperationsKeysRaw` is non-empty; with it empty, behaviour is byte-for-byte as before (tests prove it).
- Signature fields `{key_id, signature}` in the payloads named in spec §3.
- New command status `awaiting_signature`: not delivered, expired by the existing sweeper at its expiry.
- No new Go dependencies. Nothing is executed on this machine beyond unit tests with fake runners. Do not touch any Windows service. Do not run `go test ./...` inside a task.
- Go comments are prose explaining why. Commits conventional, ending with a blank line and `Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>`.

---

### Task 1: Manifests and CLI

**Files:** `internal/release/manifests.go` (+ tests: golden bytes, sign/verify round trips, wipe manifest refuses expiry > 24 h at sign time), `cmd/retune-sign/main.go` (`sign-script --key K FILE` → `FILE.sig`; `sign-command --type wipe --device D --command C --protected B --expires T --key K` → prints the sidecar JSON), tests.

- [ ] Commit `feat(release): script and wipe-order manifests`.

### Task 2: Server

**Files:** config `OPERATIONS_KEYS`; `internal/protocol/commands.go` + script protocol (signature fields); `internal/server/commands` (early verification when keys configured; wipe in enforcing mode → `awaiting_signature`; `POST /commands/{id}/signature` verifies and moves to `queued`); `internal/server/scripts` (store the signature with a version, early-verify); migration for the command status CHECK and the script version signature column; `GET /setup` exposes `operations_signing: bool`; tests in service and app packages.

- [ ] Commit `feat(server): operations signatures on scripts, PowerShell and wipe`.

### Task 3: Agent

**Files:** `internal/agent/facts/facts.go` (`OperationsKeysRaw`, `OperationsKeys()`), `internal/agent/executor` (verify `run_powershell` and `wipe` before running; wipe also checks device id = own, command id = this command, not expired), `internal/agent/scripts` scheduler (verify before running a version), `Makefile`/`build.ps1`/CI (`OPERATIONS_PUBKEYS` / `-OperationsKeys`), tests with fakes for every refusal and acceptance, and the unenforced path unchanged.

- [ ] Commit `feat(agent): require operations signatures when built to`.

### Task 4: Console, e2e, docs

**Files:** Run PowerShell dialog and script editor accept a `.sig`; wipe dialog in enforcing mode shows the exact `retune-sign sign-command …` line and a signature upload step; e2e (`TestSignedCommandsEndToEnd`: enforcing-mode server + fake agent client verify path); `README.md`; roadmap (M18 row).

- [ ] Commit `feat(console): signed scripts, PowerShell and wipe`, `test(e2e): signed commands`, `docs: signed command payloads`.
