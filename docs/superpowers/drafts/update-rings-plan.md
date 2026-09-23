# M20 Windows Update Rings Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Deadlines, pauses and target release on the `windows_update` setting, and patch-level compliance rules.

**Architecture:** Extend `protocol.Setting` validation and M8's single translation point `UpdatePolicyValues`; add two rules to `internal/server/compliance`; console form additions.

**Tech Stack:** Go 1.27, React 19 + vitest.

**Spec:** `docs/superpowers/specs/2026-09-15-m20-update-rings-design.md`

## Global Constraints

- Fields, ranges and registry value names exactly as spec §2; pause-until ≤ 35 days after it is set.
- **No update policy is applied to this machine.** Translation is tested as pure golden output; handler behaviour through the existing registry handler with a fake.
- Rules exactly as spec §3.
- No new Go dependencies. Do not touch any Windows service. Do not run `go test ./...` inside a task.
- Go comments are prose explaining why. Commits conventional, ending with a blank line and `Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>`.

---

### Task 1: Setting and translation

**Files:** `internal/protocol/profile.go` (+ tests), `internal/agent/policy/handler_update.go` `UpdatePolicyValues` (+ golden tests).

- [ ] Commit `feat(policy): update deadlines, pauses and target release`.

### Task 2: Compliance rules

**Files:** `internal/server/compliance/rules.go` (+ tests).

- [ ] Commit `feat(compliance): patch-level rules`.

### Task 3: Console, docs

**Files:** profile editor Windows Update form, compliance rule editor (per-release minimums table), tests; `README.md`; roadmap (M20 row).

- [ ] Commit `feat(console): update ring settings and patch rules`, `docs: update rings`.
