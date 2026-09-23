# M18 — Signed command payloads

Status: self-approved overnight under the user's standing directive; decisions ledgered for morning review. Builds on M1–M17 (reuses M11's `internal/release` and `retune-sign`).

## 1. What and why

M11 made it impossible for a compromised server or admin account to push an unsigned agent binary. It can still run arbitrary code everywhere by other routes: an ad-hoc `run_powershell` command, a script deployment, or a `wipe`. This milestone lets an organisation require that code the agent runs, and destructive orders it obeys, were signed by an offline **operations key** — the same Ed25519 scheme as release signing, a separate trust list.

## 2. Enforcement is decided at build time

`-X retune/internal/agent/facts.OperationsKeysRaw=<base64,…>` embeds the operations trust list. When it is empty the agent behaves as today. When it is set, the agent **requires** a valid signature on every `run_powershell` command, every script version it runs, and every `wipe` command, and refuses (reports `failed`, "this command is not signed by a trusted operations key") anything unsigned or badly signed. The server cannot turn enforcement off: it is not in any setting the server delivers.

The server reads `OPERATIONS_KEYS` (same form) only to reject bad signatures early and to tell the console which mode to present; it is not the enforcement point.

## 3. What is signed

Fixed-text manifests, as in M11:

- **Script content** (for `run_powershell` and script versions): `retune-script-manifest/v1\nsha256=<hex of the exact script bytes>\n`. Deliberately not bound to a device or command: an approved script is approved code, re-runnable anywhere. Timeouts, run-as and schedules are not signed — they cannot turn approved code into different code.
- **Wipe order:** `retune-command-manifest/v1\ntype=wipe\ndevice=<device-id>\ncommand=<command-id>\nprotected=<true|false>\nexpires=<RFC 3339 UTC>\n`. Bound to one device, one command, and an expiry ≤ 24 h, so a signed wipe cannot be replayed on another device or later.

Signatures travel in the payload as `{ "key_id": "…", "signature": "<base64>" }` (`signature` field on `RunPowerShellPayload`, on the script version row, and on `WipePayload`).

## 4. Workflow

- **Scripts:** `retune-sign sign-script --key … script.ps1` writes `script.ps1.sig`. The script editor accepts the `.sig` beside the content; the server verifies it against `OPERATIONS_KEYS` when present and stores it with the version.
- **Ad-hoc PowerShell:** the Run PowerShell dialog accepts a pasted or picked `.sig` for the exact text.
- **Wipe:** two steps, because the signature binds the command id. Queueing a wipe in enforcing mode creates the command in a new state `awaiting_signature` (not delivered). The console shows the exact `retune-sign sign-command --type wipe --device … --command … --protected … --expires …` line to run offline; the administrator uploads the resulting signature (`POST /commands/{id}/signature`), which the server verifies and the command becomes `queued`. An `awaiting_signature` command past its expiry is expired by the existing sweeper.

## 5. Out of scope

Signing profiles, app deployments and agent-side policy settings (they also make the agent act, but through typed, bounded handlers rather than arbitrary code); lock, log collection and password rotation (non-destructive or already escrowed to the server that would be the attacker).

## 6. Testing

Manifest bytes golden tests; `retune-sign sign-script` / `sign-command` round-trips; agent refuses unsigned, wrong-key, tampered-content, wrong-device, wrong-command and expired wipe orders, and accepts valid ones, in enforcing mode, and behaves exactly as before with no operations keys; server early-rejection and the `awaiting_signature` state machine; console flows. Nothing is executed on this machine beyond unit tests with fake runners.
