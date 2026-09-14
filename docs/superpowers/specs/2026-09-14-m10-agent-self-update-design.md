# M10 — Agent self-update

**Spec:** extends `docs/superpowers/specs/2026-09-12-core-platform-design.md`
(agent self-update was listed there as out of scope for the core platform).

**Builds on:** M1–M9, all merged. Reuses the M5 assignment engine and the
item-kind seams M9 generalised.

Retune can deploy software to the machines it manages but cannot update itself.
A defect in the agent today has no remedy short of re-running the MSI on every
device — which is the gap this milestone closes, and which M9 demonstrated in
the most direct way available: an agent bug made a whole feature inert, and the
only fix was to stop a service, rebuild, and start it again by hand.

An **agent version** is an uploaded build assigned to a group. The agent
downloads it, verifies it, swaps to it under supervision, and goes back to the
previous build if the new one cannot reach the server.

## 1. Decisions

| Question | Decision | Why |
|---|---|---|
| Where do binaries come from? | Retune hosts them. Uploaded by an administrator, stored under `DATA_DIR`, served to agents over the existing mTLS channel. | Self-update has no third party equivalent to winget. Hosting keeps an on-prem or air-gapped install self-sufficient, and the server already authenticates every agent. |
| How is a bad build survived? | The previous build is kept. A new agent must **check in successfully** within a deadline or it is rolled back. | A broken agent cannot be fixed remotely — the exact problem this milestone exists to solve, so it must not cause it. A bad build costs one check-in cycle instead of a truck roll. |
| Who updates, and when? | Assigned to groups, like every other item kind. | Pilot on one group and widen. No new scheduling concepts, and the console page looks like the ones that exist. |
| How is a build trusted? | SHA-256 recorded at upload, verified by the agent after download. | The channel is already mutual TLS against the internal CA. This defends against corruption and a tampered artifact store, proportionate without introducing code-signing key management. |
| Where does the managed binary live? | `DATA_DIR\bin\<version>\`, with the service's `binPath` repointed. The MSI's copy in `Program Files` is a bootstrap that is never modified. | Sidesteps the Windows Installer component conflict entirely rather than managing it, and means a running image is never modified. |
| Is a downgrade allowed? | Yes. Assigning an older version is a deliberate act and must work. | It is how a fleet is recovered from a bad build without touching every machine. The agent compares versions for difference, not ordering. |

## 2. What the probe established

Run on a real Windows machine before this design was written, with a throwaway
service (`RetuneProbeSvc`, LocalSystem, under `C:\ProgramData\RetuneProbe`),
removed afterwards:

| Test | Result |
|---|---|
| Overwrite the running image | **Refused** — "being used by another process" |
| Rename the running image aside | **Allowed** |
| Write a new binary at the original path | **Allowed** |
| Service restarts itself via a detached helper | **Worked** — v1 logged `stopping`, v2 started 3 seconds later |
| Delete the superseded image afterwards | **Clean**, no reboot-delayed delete needed |

Two conclusions. A service genuinely cannot stop itself synchronously — it
would be waiting on its own shutdown — so the restart must leave the process,
and a detached helper does the job in about three seconds. And because
renaming a live image is permitted, in-place update is *possible*; this design
does not use it, because repointing `binPath` is better, but it remains a
sound fallback.

### What reading the code established

- **The MSI owns `retune-agent.exe` as a keypath component** in
  `ProgramFiles64Folder\Retune` (`deploy/msi/Package.wxs`). An in-place
  overwrite there fights Windows Installer: a repair or major upgrade can
  revert it, and an uninstall deletes the file it believes it owns.
- **WiX-installed services get no recovery actions and no arguments.** The
  manual `retune-agent install` path sets three restart actions and passes
  `--data-dir`; the MSI path does neither. Rollback therefore cannot rely on
  the service control manager, and any repoint must preserve whichever
  argument form is already in place.
- **`facts.AgentVersion` is a hardcoded constant**, unrelated to the version
  CI stamps on the MSI. See §6.

## 3. On-disk layout

```
C:\Program Files\Retune\retune-agent.exe          MSI-owned bootstrap. Never modified.
C:\ProgramData\Retune\bin\<version>\retune-agent.exe   Managed versions.
C:\ProgramData\Retune\supervisor.exe              A copy of the known-good build,
                                                  made for the duration of an update.
C:\ProgramData\Retune\update.json                 What is being attempted, and from what.
```

The service's `binPath` is the single source of truth for which version runs.
Before the first self-update it points at `Program Files`; afterwards it points
into `bin\<version>\` and `Program Files` is never touched again.

`DATA_DIR` is already ACL'd to SYSTEM and Administrators with inheritance
removed (`secureDataDir`), so a binary running from there is no less protected
than one in `Program Files`.

`update.json`:

| Field | Meaning |
|---|---|
| `from_version`, `from_bin_path`, `from_args` | Everything needed to put the service back exactly as it was |
| `to_version`, `to_bin_path` | What is being attempted |
| `started_at`, `deadline` | When the supervisor gives up |
| `status` | `pending`, `succeeded`, or `rolled_back` |
| `detail` | Why it was rolled back, for the restored agent to report |

## 4. The update

Performed by the agent currently running, on its own check-in cycle:

1. The assigned version differs from the running version. (Difference, not
   ordering — a downgrade is a legitimate instruction.)
2. Download to `bin\<version>\retune-agent.exe.part` and verify the SHA-256 the
   server recorded at upload. A mismatch reports `failed` and stops; nothing on
   disk has changed that matters.
3. Rename `.part` into place.
4. Write `update.json`, capturing the current `binPath` **and its arguments**
   so the service can be restored exactly — an MSI-installed service carries no
   `--data-dir` and a manually-installed one does, and a repoint that loses
   that argument sends the new agent looking for its identity in the wrong
   directory, where it would try to re-enrol with a spent token.
5. Copy the running binary to `supervisor.exe`. A copy, not the service image:
   it is not locked, it is not the service, and it survives the service being
   stopped.
6. Spawn `supervisor.exe supervise-update` detached, and carry on until stopped.

## 5. The supervisor, and rollback

The supervisor is **the known-good build supervising its own replacement**.
That is the property that makes rollback trustworthy: the code deciding
whether the new version works is the code that already worked.

1. Stop the service, bounded by a timeout.
2. Repoint `binPath` to `to_bin_path`, preserving `from_args`.
3. Set service recovery actions — three restarts. WiX-installed services have
   none, so a crash-on-start would otherwise never be retried.
4. Start the service.
5. Wait for proof.

**Proof of life is a successful check-in, not a successful start.** A binary
that launches but cannot reach the server is precisely the failure this
milestone exists to prevent. The new agent sets `update.json` to `succeeded`
only after it has actually reached the server.

If the deadline passes without that: stop the service, repoint `binPath` back
to `from_bin_path` with `from_args`, set `status` to `rolled_back` with a
reason, and start the service again.

The restored agent reads `update.json` at startup, reports the failed version
and the reason, and marks the record `reported` — it does not delete it. The
record is also the only memory that this version failed on this device, and
deleting it would let the very next item of the very same check-in decide to
install the same broken build again. The console then shows *"3 devices rolled
back from 0.2.0"* rather than silence — which is what turns a bad build from a
mystery into a pilot group telling you something.

On success the supervisor deletes `update.json` and prunes versions older than
the current and previous. It does not remove itself: a running image cannot
delete its own file, and scheduling one for the next reboot is more machinery
than the problem deserves. `supervisor.exe` stays in the data directory, is
overwritten by the next update, and goes with the whole directory when
`cleanup` runs at uninstall.

### Known limits, stated rather than glossed

- **A reboot inside the update window kills the supervisor.** Recovery actions
  cover crash-on-start; they cannot cover starts-but-never-checks-in. The
  window is seconds and the gap is narrow; a second watchdog would cost more
  than it returns. Documented, not defended against.
- **Only current and previous are kept.** Rolling back two versions means
  assigning the older one, which is an ordinary deliberate instruction.

## 6. Version identity — a precondition, not a nicety

`internal/agent/facts/facts.go` declares `const AgentVersion = "0.1.0-dev"`,
unrelated to the `-Version` CI passes to `deploy/msi/build.ps1`. An update loop
comparing assigned against reported would see an updated agent still reporting
`0.1.0-dev`, conclude it had not updated, and **update it again, forever,
across the fleet.**

So build-time injection lands first: `-ldflags -X
retune/internal/agent/facts.AgentVersion=<version>` in the `Makefile`,
`deploy/msi/build.ps1` and `.github/workflows/ci.yml` together.

And the agent **refuses to participate in self-update at all while its version
is the placeholder**, reporting that as the reason. A feature that declines to
run is far better than a loop that hammers every machine in the fleet.

## 7. Server side

### Storage

`DATA_DIR/agents/<version>/retune-agent.exe`, beside the CA and the secret key,
with metadata in Postgres: version, SHA-256, size in bytes, uploader, upload
time, optional notes.

Filesystem rather than a `bytea` column: multi-megabyte blobs do not belong in
database backups, and `DATA_DIR` is already what the README tells you to back
up. This does change the Docker volume sizing story, and the README must say
so.

### Tables — `0009_agent_versions.{up,down}.sql`

```
agent_versions    id (uuid, PK), tenant_id, version (text), sha256,
                  size_bytes, notes, created_at, created_by
                  UNIQUE (tenant_id, version)
```

The primary key is a UUID because `assignments.item_id` is `uuid NOT NULL`,
like every other item kind. The version string is what people read and what
the agent compares, so it is unique per tenant — uploading the same version
twice is a mistake, not a new build.

No change to `assignments` or `device_item_status`. `item_kind` is free text
with no CHECK constraint, so a fourth kind needs no migration there.

### Routes

```
POST   /api/admin/v1/agent-versions           upload; admin only; audited
GET    /api/admin/v1/agent-versions           list
GET    /api/admin/v1/agent-versions/{id}      one build
DELETE /api/admin/v1/agent-versions/{id}      remove a build, its file and its assignments
GET    /api/agent/v1/agent-versions/{id}/binary   stream, gated on assignment
```

Everything is addressed by the row's UUID, as the other three kinds are.
`DELETE` removes the stored file and calls `DeleteAssignmentsForItem`, so a
deleted build cannot leave devices being told to install something that no
longer exists — the rule M9 established. Deleting the version a device is
currently *running* is allowed and harmless: the agent is not asked to change.

The download is the product's **first non-JSON response and first streaming
body**. The client's `do` helper marshals and decodes JSON and imposes a flat
60-second timeout; a multi-megabyte download on a slow link needs its own path
with a separate, longer budget. The upload needs a size cap and must record the
hash as it receives, not afterwards.

The download endpoint is gated on assignment with `DeviceHasItem`, like every
other agent endpoint.

### The fourth item kind

`protocol.ItemKindAgent = "agent"`, through the four seams:

| Seam | Change |
|---|---|
| `adminapi.optionsParsers` | an `agent` entry. One option: `deadline_seconds`, 60–3600, default 600 — how long the supervisor waits for the new agent to check in before rolling back. Ten minutes comfortably spans a service restart plus a check-in interval, without stranding a device for an hour. |
| `agentapi.itemVersion` | an `agent` case resolving the assigned version |
| `session.ItemSyncer` | an `agentSyncer`, `RunOnEmpty()` false |
| console | an Agent versions page |

`RunOnEmpty()` is false: an agent that stops being assigned a version keeps the
one it is running. Unassignment is not a downgrade instruction.

`protocol.Item.Version` is an integer across all kinds, so it cannot carry a
version string. An agent build is immutable — a new build is a new row, never
an edit — so the item's numeric version is always `1`, and the version string
travels in the fetched definition alongside the hash and size. The agent
compares that string against its own.

## 8. Failure modes

| Failure | Reported |
|---|---|
| Agent version is the placeholder | `failed` — "this build has no injected version, so it will not self-update" |
| Download fails or is cut short | `failed`, with the transport error; nothing swapped |
| SHA-256 mismatch | `failed` — the hash the server recorded and the hash received |
| No disk space for the new version | `failed`, naming the path |
| Service will not stop within the timeout | `failed`; no repoint attempted |
| New agent never checks in before the deadline | `rolled_back`, reported by the restored agent with the failed version |
| New agent crashes on start | Recovery actions retry three times; then the deadline expires and it is rolled back |
| Reboot inside the update window | Not recovered automatically; documented in §5 |

## 9. Testing

**Unit, no machine:** version comparison and the difference-not-ordering rule;
`update.json` round-trip including the arguments capture; the decision to
update, skip, or refuse on a placeholder version; SHA-256 verification
including a deliberate mismatch.

**Agent, against fakes:** a fake download source and a fake service controller,
covering a clean update, a hash mismatch, a service that will not stop, a new
agent that never checks in (rollback), and a rollback whose restored agent
reports the failure.

**Integration, real Postgres:** upload, list, delete; the download gated on
assignment; check-in offering an agent item; per-device status.

**E2E:** upload a build, assign it, check in, report, read the rollup.

## 10. Verification on this machine

The M9 lesson was that only running it finds some defects. So this milestone is
verified on real hardware, through the installed service, in this order — and
crucially **the rollback path is exercised deliberately, not assumed**:

1. Install the current agent from the MSI; confirm it enrols and reports an
   injected version.
2. Upload a genuine newer build. Assign it. Confirm the service repoints into
   `bin\<version>\`, the new version checks in, and the console shows it.
3. Confirm `Program Files` is untouched and the old version directory is pruned.
4. **Upload a deliberately broken build** — one that starts and then exits, or
   cannot reach the server — assign it, and confirm the supervisor rolls back,
   the previous version resumes checking in, and the console reports the failed
   version. This is the acceptance test for the whole milestone.
5. Assign the older version deliberately and confirm the downgrade works.
6. Uninstall, remove the data directory, and confirm the machine is as it was.
