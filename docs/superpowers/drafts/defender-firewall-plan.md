# M15 Defender and Firewall Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Report Defender and firewall state in inventory, add a `defender` profile setting kind, and add three compliance rules over the new data.

**Architecture:** Additive, `omitempty` protocol fields; WMI read functions in the Windows collector; a PowerShell-backed handler modelled on `FirewallProfileHandler`; rule-engine additions in `internal/server/compliance`.

**Tech Stack:** Go 1.27 (`github.com/yusufpapurcu/wmi` already a dependency), React 19 + vitest.

**Spec:** `docs/superpowers/specs/2026-09-15-m15-defender-design.md`

## Global Constraints

- New protocol fields are `omitempty` and nil-safe everywhere; an inventory without them must parse and evaluate rules as unknown.
- **Never change a Defender or firewall setting on this machine.** Handlers take the `PowerShell` func; tests pass a fake. The collector's WMI-row-to-protocol mapping is a pure function tested on fixtures; the WMI query itself is not run in tests.
- `defender` fields and value mappings exactly as spec §3; only named fields are read or written.
- Rule types and bounds exactly as spec §4.
- No new Go dependencies. Do not install, start, stop or touch any Windows service. Do not run `go test ./...` inside a task.
- Go comments are prose explaining why. Commits conventional, ending with a blank line and `Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>`.

---

### Task 1: Protocol and collector

**Files:** `internal/protocol/inventory.go` (`DefenderStatus`, `FirewallProfileState`, fields on `Inventory`), `internal/agent/inventory/collector_windows.go` (`collectDefender() *protocol.DefenderStatus`, `collectFirewall() []protocol.FirewallProfileState`, wired into `Collect`; each built from a row struct via a pure `defenderFromRow(row) *protocol.DefenderStatus` / `firewallFromRows(rows) []…`), tests in `internal/protocol/inventory_test.go` and `internal/agent/inventory/collector_windows_test.go` (pure mapping functions on fixtures, including the absent-namespace case).

- [ ] TDD; commit `feat(agent): report Defender and firewall state in inventory`.

### Task 2: `defender` setting kind

**Files:** `internal/protocol/profile.go` (kind constant, setting fields, validation, the setting's identity key for conflict detection — one `defender` setting per profile, key `defender`), `internal/agent/policy/handler_defender.go` (+ `_test.go`), registration in `internal/agent/policy/handlers*.go` alongside the firewall handlers.

- [ ] Handler tests with a fake `PowerShell`: `Get` reports exactly the differing named fields; `Set` issues one `Set-MpPreference` naming only those fields with the mapped values; revert restores captured values; a write that does not stick produces the Tamper Protection detail. Protocol validation tests. Commit `feat(agent): defender setting kind`.

### Task 3: Compliance rules

**Files:** `internal/server/compliance/rules.go` (+ tests) — three new types, strict parsing, details per spec §4.

- [ ] Table tests: compliant, non-compliant, unknown, boundary for each. Commit `feat(compliance): Defender and firewall rules`.

### Task 4: Console

**Files:** `web/src/pages/DeviceDetail.tsx` (Security section), profile editor (the `defender` kind with its five optional fields), compliance rule editor (three new types), `web/src/api/types.ts`; tests.

- [ ] `npx vitest run`, `npx tsc --noEmit -p .`. Commit `feat(console): Defender status, policy and rules`.

### Task 5: End to end, docs

**Files:** `test/e2e/e2e_test.go` (inventory with Defender real-time off → `defender_realtime` non-compliant; on → compliant), `README.md` (Defender section; rule table additions), roadmap (M15 row).

- [ ] Commit `test(e2e): Defender compliance end to end` and `docs: Defender and firewall`.
