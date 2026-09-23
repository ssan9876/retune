# M15 — Defender and firewall: status, policy, compliance

Status: approved by the user on 2026-09-22 ("yes for the defender and firewall"). Promoted from `docs/superpowers/drafts/defender-firewall-spec.md` and revised against the code after M14. Builds on merged M1–M14.

**No Defender or firewall setting is changed on the development machine.** Applying policy is built and tested with a fake PowerShell only. Reading status there is read-only and allowed.

## 1. What and why

Today an administrator can't see whether a device's antivirus is running, whether its signatures are current, or whether its firewall is on. Inventory reports none of it, so M12 couldn't offer compliance rules for them. This milestone:
- reports Microsoft Defender Antivirus status and the effective firewall state in inventory;
- adds a `defender` setting kind, so a configuration profile can set the core Defender preferences;
- adds three compliance rules over the new data.

## 2. Inventory (agent)

`protocol.Inventory` gains two `omitempty` fields, so older agents and servers keep working with each other.

### `Defender *DefenderStatus`
- **Source:** WMI `root\Microsoft\Windows\Defender`, class `MSFT_MpComputerStatus`.
- **Fields:**
  - `running_mode` (`AMRunningMode`: e.g. `Normal`, `Passive Mode`, `EDR Block Mode`)
  - `antivirus_enabled`, `realtime_enabled`, `tamper_protected`
  - `signature_version`, `signature_updated_at`
  - `last_quick_scan_at` and `last_full_scan_at`, both omitted when Defender reports no scan (it returns a zero date).
- **Missing data:** nil when the namespace or class isn't there (Defender not installed, or removed by third-party antivirus). A nil block is read as "not reported", never guessed.

### `Firewall []FirewallProfileState`
- **Shape:** `{profile: domain|private|public, enabled: bool}`.
- **Source:** the Windows firewall API (`HNetCfg.FwPolicy2`, `FirewallEnabled` for profile types 1, 2 and 4), through `go-ole`. `go-ole` is already in the module graph via the WMI library, so this adds no dependency.
- **Why not the draft's WMI class:** `MSFT_NetFirewallProfile` reads the *locally stored* settings by default. Group Policy can override those, so that class can report a profile on when it is actually off, or the reverse. The firewall API reports what is actually in effect. Both approaches were checked read-only on the development machine on 2026-09-22.
- **Missing data:** nil when the API can't be reached.

**Structure and upload frequency:**
- Each block is read in its own function. A failure is logged and leaves that block nil; it never fails the rest of inventory.
- The mapping from raw rows to protocol structs is a pure function, tested on fixtures.
- The server already decides when inventory is due (daily, or on demand), so signature fields changing every day don't add uploads.

## 3. The `defender` setting kind

`protocol.KindDefender = "defender"` has five optional fields. Only the fields named in a setting are read or written, and at least one must be named.

| field | `Set-MpPreference` parameter | values |
|---|---|---|
| `realtime_monitoring` | `-DisableRealtimeMonitoring` (inverted) | `true` / `false` |
| `cloud_protection` | `-MAPSReporting` | `off` 0, `basic` 1, `advanced` 2 |
| `sample_submission` | `-SubmitSamplesConsent` | `prompt` 0, `safe` 1, `never` 2, `all` 3 |
| `pua_protection` | `-PUAProtection` | `off` 0, `on` 1, `audit` 2 |
| `cloud_block_level` | `-CloudBlockLevel` | `default` 0, `moderate` 1, `high` 2, `high_plus` 4, `zero_tolerance` 6 |

**Conflicts.** The identity is `defender:preferences`: one set of preferences per machine, the same model as `windows_update:policy`. Two profiles that name different values for the same machine's Defender preferences are a conflict and neither is applied, even if the fields they name don't overlap. Splitting the identity per field would let two half-policies combine into something nobody wrote.

**The handler** (`DefenderHandler`) follows `FirewallProfileHandler`, and takes the `PowerShell` func so tests can pass a fake:
- `Get` reads `Get-MpPreference` for the named fields and records them, so a revert can put them back.
- `Test` compares the named fields.
- `Set` issues one `Set-MpPreference` naming only those fields.
- `Revert` sets the recorded values back.

**Tamper Protection** makes `Set-MpPreference` succeed while changing nothing. It was on for the development machine's Defender when this was checked. `Set` therefore re-reads after writing. If any named field didn't take, it returns an error saying so: "Defender did not accept the change to <fields>; Tamper Protection may be on." The engine reports that as the setting's error, instead of its generic "applied but still does not match".

Validation sits with the other kinds in `internal/protocol/profile.go`. The console's profile editor gains the kind.

## 4. Compliance rules (server)

| type | params | compliant when | unknown when | non-compliant when |
|---|---|---|---|---|
| `defender_realtime` | none | antivirus and real-time protection both on, in `Normal` mode | no Defender block; or Defender is in passive or EDR block mode (another antivirus is primary, so Defender's own real-time state says nothing) | Defender is in `Normal` mode with antivirus or real-time protection off |
| `defender_signatures_within` | `days` 1–30 | signatures updated within `days`, measured from `signature_updated_at` **at evaluation time** | no Defender block, or no update time | older than `days` |
| `firewall_enabled` | `profiles`: a non-empty subset of `domain`, `private`, `public`; absent means all three | every named profile on | no firewall block, or a named profile not reported | any named profile off |

The draft used the agent's own "signature age" number. That number freezes when a device stops reporting, so a machine that goes quiet would stay compliant forever. Measuring from the update time is what lets the 15-minute compliance sweeper catch it.

The console's rule editor gains the three types.

## 5. Console

A device's page gains a **Security** section showing:
- Defender's mode, real-time protection, Tamper Protection, and signature version and age;
- the last quick and full scans;
- each firewall profile on or off.

Anything missing shows as "not reported".

## 6. Testing

- **Protocol:**
  - inventory without the new blocks parses, and hashes the same as before;
  - `defender` setting validation;
  - the identity.
- **Collector:** the pure mapping functions, on fixtures, including:
  - a zero scan time;
  - an empty result (no Defender);
  - an unknown profile.
- **Handler (fake PowerShell):**
  - `Test` compares only the named fields;
  - `Set` sends one `Set-MpPreference` with only those fields and their mapped values;
  - `Revert` restores the recorded values;
  - a write that doesn't take returns the Tamper Protection error.
- **Rules:** table tests covering compliant, non-compliant, unknown and the boundary for each rule, including passive mode and a stale signature measured at evaluation time.
- **End to end:** inventory with real-time protection off makes `defender_realtime` non-compliant; turning it on makes it compliant.
- **Console:** tests for the Security section and both editors.
