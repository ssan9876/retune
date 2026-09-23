# M16 Certificate, Wi-Fi and VPN Settings Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Three new configuration-profile setting kinds — `certificate`, `wifi`, `vpn` — with sealed secrets inside settings.

**Architecture:** Validation in `internal/protocol/profile.go`; sealing/redaction in `internal/server/profiles`; agent handlers in `internal/agent/policy` modelled on `FirewallProfileHandler`, each Windows side effect behind a runner func with a fake in tests; console editor forms.

**Tech Stack:** Go 1.27 (`crypto/x509`, `encoding/pem`, `encoding/xml`), React 19 + vitest.

**Spec:** `docs/superpowers/specs/2026-09-15-m16-network-profiles-design.md`

## Global Constraints

- Kinds `certificate`, `wifi`, `vpn`; fields, bounds and identity keys exactly as spec §2.
- A certificate PEM containing any `PRIVATE KEY` block is invalid. Thumbprint is SHA-1 of the DER, uppercase hex, computed server-side.
- Wi-Fi passphrase and L2TP PSK: sealed with `secrets.Key`, AAD `"<profile-id>/<setting-key>"`; every admin API response shows `{"sealed": true}` in their place; only the agent-API profile definition carries plaintext.
- **Never apply a certificate, Wi-Fi or VPN setting on this machine.** Handlers take runner funcs; tests pass fakes. WLAN XML rendering is a pure function with golden files.
- No new Go dependencies. Do not touch any Windows service. Do not run `go test ./...` inside a task.
- Go comments are prose explaining why. Commits conventional, ending with a blank line and `Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>`.

---

### Task 1: Protocol validation

**Files:** `internal/protocol/profile.go` (+ `profile_test.go`) — the three kinds, their fields and validation, identity keys; the certificate thumbprint computed and stored on the setting at validation.

- [ ] Table tests for every bound and the private-key refusal. Commit `feat(protocol): certificate, Wi-Fi and VPN setting kinds`.

### Task 2: Server sealing and redaction

**Files:** `internal/server/profiles/` (seal on create/update, redact in every admin-facing read, unseal only in the definition built for the agent API; an update that sends `{"sealed": true}` keeps the stored secret), tests at service level and one app-level test asserting no admin endpoint (profile get, versions list, settings list, audit) ever contains the plaintext.

- [ ] Commit `feat(profiles): seal secrets inside settings`.

### Task 3: Agent handlers

**Files:** `internal/agent/policy/handler_certificate.go`, `handler_wifi.go` (+ `wlanxml.go` with golden files under `testdata/`), `handler_vpn.go`, tests for each; registration beside the existing handlers.

- [ ] Fake-runner tests: get/set/revert, pre-existing left alone on revert, Wi-Fi `not_applicable` without a wireless adapter, only managed fields compared. Commit `feat(agent): certificate, Wi-Fi and VPN handlers`.

### Task 4: Console

**Files:** profile editor forms for the three kinds (PEM paste with parsed subject/issuer/expiry/thumbprint preview via the server's validation response, write-only secret inputs), `web/src/api/types.ts`, tests.

- [ ] Commit `feat(console): network profile settings`.

### Task 5: End to end, docs

**Files:** `test/e2e/e2e_test.go` (a profile with a Wi-Fi setting: admin responses redacted, the enrolled device's definition carries the passphrase), `README.md`, roadmap (M16 row).

- [ ] Commit `test(e2e): network profile settings` and `docs: certificate, Wi-Fi and VPN settings`.
