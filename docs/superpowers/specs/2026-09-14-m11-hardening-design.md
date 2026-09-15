# M11 — Hardening: signed agent builds, race detection, tenant scoping

Status: approved design. Builds on merged M1–M10. Extends the core-platform
spec (`2026-09-12-core-platform-design.md`) and the M10 self-update spec
(`2026-09-14-m10-agent-self-update-design.md`).

## 1. Why

M10 made the agent run code the server hands it. Today anyone holding an admin
session can upload any 128 MiB of bytes and have every device in a group run
them as LocalSystem. mTLS and the recorded SHA-256 protect the *channel*; nothing
protects the *content*. This milestone puts an offline release key between an
admin account and the fleet, and clears three pieces of debt the M10 review
surfaced: no race detector has ever run, a successful self-update leaves no
trace in the console, and every single-row store query ignores `tenant_id`.

## 2. Threat model

In scope: an attacker who has an admin session (stolen cookie, phished
password, malicious admin) or has compromised the server's database or data
directory. Neither can produce a valid signature, so neither can push code.

Out of scope: an attacker holding the release private key; an attacker with
code execution on the device as SYSTEM; the build machine itself. Signed
command payloads (protecting ad-hoc scripts from a compromised server) are a
separate milestone.

## 3. Release signing

### 3.1 Key and manifest

- Algorithm: Ed25519 (stdlib `crypto/ed25519`). No new dependencies.
- **Manifest** — the bytes that are signed — is a fixed text form, so there is
  no JSON canonicalisation to get wrong:

  ```
  retune-agent-manifest/v1
  version=<version>
  sha256=<lowercase hex of the binary>
  ```

  Exactly those three lines, each terminated by `\n`.
- **Key ID** is the first 8 bytes of SHA-256 over the raw 32-byte public key,
  lowercase hex (16 characters). It lets a verifier pick a key from a list
  without trying every one; it carries no security weight.
- **Sidecar** `<binary>.sig` is JSON:

  ```json
  {"version":"1.4.0","sha256":"<hex>","key_id":"<16 hex>","signature":"<base64 std, 64 bytes>"}
  ```

### 3.2 Package and tool

- `internal/release`: `Manifest{Version, SHA256}`, `(Manifest) Bytes()`,
  `Sign(priv, Manifest) Signature`, `Verify(pubs []PublicKey, Manifest,
  Signature) error`, `KeyID(pub) string`, `ParseTrustList(s string)
  ([]PublicKey, error)` (comma-separated base64 raw public keys), key
  encode/decode helpers. Pure functions, fully unit-tested, shared by the
  server, the agent and the CLI.
- `cmd/retune-sign`:
  - `keygen --out <dir>` writes `release.key` (0600, base64 seed) and
    `release.pub` (base64 public key) and prints the key ID and the public key.
    Refuses to overwrite.
  - `sign --key <file|env:RELEASE_KEY> --version <v> <binary>` writes
    `<binary>.sig`.
  - `verify --trust <base64,...> <binary> <binary>.sig` exits 0/1 and prints
    the manifest and which key verified.

### 3.3 Where the keys live

- **Agent** embeds its trust list at build time, beside the version:
  `-X retune/internal/agent/facts.TrustedKeysRaw=<base64>,<base64>`.
  `facts.TrustedKeys() []release.PublicKey` parses it once; a parse error is
  treated as an empty list. An empty list means the build cannot self-update
  (§3.5).
- **Server** reads `AGENT_RELEASE_KEYS` (config file key `agent_release_keys`),
  the same comma-separated form. It is optional at startup — a server that
  never self-updates agents needs none — but an upload with it unset is refused
  with `503 release_keys_unset: set AGENT_RELEASE_KEYS to the public keys that
  sign agent builds`. Nothing silently accepts.
- **Rotation**: ship a build signed by the old key whose trust list is
  old+new, then a build signed by the new key whose list is new only. Add the
  new key to `AGENT_RELEASE_KEYS` before the second upload. No runtime trust
  changes on devices; nothing a compromised server can alter.

### 3.4 Build integration

- `Makefile` `agent` target: if `RELEASE_KEY` is set (path or `env:` form) it
  signs `bin/retune-agent.exe` and embeds `RELEASE_PUBKEYS` (required; the
  trust list is always stated explicitly); if unset the binary is unsigned
  and carries no trust list, and the target prints one line saying so.
- `deploy/msi/build.ps1` takes `-ReleaseKey` / `-TrustedKeys` with the same
  behaviour and copies the `.sig` beside the MSI.
- CI: each run does `retune-sign keygen` into a temp dir and builds with it,
  so CI artefacts are signed by a throwaway key and the signing path is
  exercised on every run. Release signing with a real key is an operator's
  job, not CI's.

### 3.5 Agent-side verification

- `protocol.AgentVersionResponse` gains `KeyID` and `Signature`.
- In `selfupdate.Syncer.stage`, after the download's hash has matched,
  the agent rebuilds `Manifest{def.Version, def.SHA256}` and verifies
  `def.Signature` with `def.KeyID` against `facts.TrustedKeys()`. Failure is
  handled exactly like a hash mismatch: the version directory is removed, the
  outcome is reported `failed` with `"signature did not verify against any
  trusted release key (key <id>)"`, and no record is written.
- `Decide` gains a refusal after the same-version check, so an agent already
  on the assigned build stays quiet: `trusted == 0` →
  `"this build has no trusted release keys, so it will not self-update"`,
  reported like the uninjected case whenever it fires. `Decide`'s signature
  becomes `Decide(running, assigned string, injected bool, trusted int,
  attempted Record)`.
- The supervisor is unchanged: it only runs what `stage` verified.

## 4. Upload

- `POST /agent-versions?version=&notes=` keeps its raw octet-stream body. The
  sidecar travels in one header, `X-Retune-Signature`, holding the base64 of
  the `.sig` JSON. Version and notes stay query parameters.
- Order of checks, each failure a `400` naming the reason (except the first,
  `503`):
  1. `AGENT_RELEASE_KEYS` is set.
  2. Header present, base64 decodes, JSON parses, `signature` is 64 bytes.
  3. `key_id` names a configured key.
  4. Body streams to `.part` with SHA-256 (as today, same size limit).
  5. Computed hash equals manifest `sha256`.
  6. Declared `version` equals manifest `version`.
  7. Signature verifies.
- Any failure after step 4 removes the artefact. Every rejection writes audit
  `agent_version.rejected` with the reason, declared version and actor: a
  refused upload is the event this milestone exists to notice.
- Migration `0010_agent_version_signatures`: `agent_versions` gains
  `key_id text NOT NULL` and `signature text NOT NULL`. The table shipped in
  M10 and nothing is deployed, so the columns are required outright; the down
  migration drops them.
- The M10 "binary contains its version string" scan is deleted; the signed
  manifest supersedes it and closes the `v1.2.3`/`1.2.3` fleet-rollback hole
  properly (step 6).
- `GET /agent-versions/{id}`, the list, and the agent's version endpoint all
  return `key_id` and `signature`.
- Console `AgentVersions` page: a second file picker for the `.sig`
  (required); the page reads it, base64-encodes it, and sends the header via
  `api.postBinary`, which gains an optional headers argument. The versions
  table shows the key ID.

## 5. Successful self-updates are visible

Server-side inference, no agent change. In the agent API's check-in handler,
after `EffectiveItems` is computed: for each item of kind `agent` whose
version string equals the device's reported `agent_version`, call
`SetItemStatus` with `succeeded` and detail `"running this version"` unless
the existing row is already `succeeded`. This also marks a device that arrived
at the version by MSI, which is the truth. The version's status page then
shows succeeded and failed side by side.

## 6. Race detector

- Linux CI job: `go test -race ./...`. Windows job unchanged (`-short`, no
  CGO).
- Any race the detector finds during this milestone is fixed in this
  milestone, not deferred.
- The existing `TestSyncSerialisesConcurrentCalls` and
  `TestCheckedInIsNotBlockedByASyncThatIsDownloading` are the seams the M10
  review named; they run under the detector like everything else.

## 7. Tenant scoping on single-row queries

Every store query of the form `WHERE id = $1` — getters, updates and deletes —
gains `AND tenant_id = $2`. Method signatures take `tenantID uuid.UUID` before
`id`. Services pass `store.DefaultTenantID` (the only tenant until
multi-tenancy ships). Tables: `enrollment_tokens`, `devices`, `commands`,
`admins`, `device_groups`, `assignments`, `scripts`, `profiles`, `apps`,
`agent_versions`. The plan confirms each table's column before the task runs.
One test per table proves a row under another tenant is not found (and not
updated, not deleted).

## 8. Out of scope

Signed command payloads; key storage in a KMS; signing the server binary or
the MSI itself (the MSI remains unsigned per M4); revoking a compromised key
on devices without shipping a build.

## 9. Verification on this machine

Controller only, at the end, no real service touched during implementation:

1. `retune-sign keygen`; build a signed 0.3.0 MSI embedding that public key;
   install; confirm enrolment.
2. Start the server with `AGENT_RELEASE_KEYS` set. Upload a signed 0.3.1 build
   with its `.sig` through the console: accepted, key ID shown.
3. Upload the same bytes with a `.sig` from a different key: `400`, audit
   `agent_version.rejected`. Upload with no header: `400`. Upload with
   `version=0.3.9` declared against a `0.3.1` manifest: `400`.
4. Assign 0.3.1; the service updates through the full M10 path with the
   signature verified on the device; the version's status page shows
   `succeeded` for the device.
5. Upload a 0.3.2 signed by a key the *server* trusts but the *agent* does
   not (a second key added to `AGENT_RELEASE_KEYS` only) and assign it: the
   agent downloads it, fails signature verification, reports `failed`, and
   stays on 0.3.1 with no record written.
6. Uninstall; remove the data directory; server and database torn down.
