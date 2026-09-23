# M15 — Defender and firewall: status, policy, compliance

Status: self-approved overnight under the user's standing directive; decisions ledgered for morning review. Builds on M1–M14 (needs M12's rule engine). **No Defender or firewall setting is changed on this machine** — policy application is built and tested with fakes only.

## 1. What and why

An administrator cannot see today whether a device's antivirus is running, whether its signatures are current, or whether its firewall is on — inventory reports none of it, so M12 could not make them compliance rules. This milestone reports Microsoft Defender Antivirus status and firewall profile state in inventory, adds a `defender` setting kind so a configuration profile can set the core Defender preferences, and adds three compliance rules over the new data.

## 2. Inventory additions (agent)

`protocol.Inventory` gains, all `omitempty` so older agents and servers keep working:

- `Defender *DefenderStatus` — from WMI `root\Microsoft\Windows\Defender`, class `MSFT_MpComputerStatus`: `am_running_mode` (e.g. "Normal", "Passive Mode", "EDR Block Mode"), `antivirus_enabled`, `realtime_enabled`, `tamper_protected`, `signature_version`, `signature_updated_at`, `signature_age_days`, `last_quick_scan_at`, `last_full_scan_at`. Nil when the namespace is absent (Defender not installed, or a third-party AV has taken over and Defender reports nothing) — reported as "unknown", never guessed.
- `Firewall []FirewallProfileState` — from WMI `root\StandardCimv2`, class `MSFT_NetFirewallProfile`: `{profile: domain|private|public, enabled: bool}`.

Both are read-only WMI queries, in the existing collector style (`wmi.QueryNamespace`), each in its own function so a failure of one leaves the rest of inventory intact.

## 3. `defender` setting kind (agent policy)

A new `protocol.KindDefender` setting with a fixed, deliberately small set of fields, each optional (only named fields are enforced):

| field | cmdlet parameter | values |
|---|---|---|
| `realtime_monitoring` | `-DisableRealtimeMonitoring` (inverted) | `true`/`false` |
| `cloud_protection` | `-MAPSReporting` | `off` (0), `basic` (1), `advanced` (2) |
| `sample_submission` | `-SubmitSamplesConsent` | `prompt` (0), `safe` (1), `never` (2), `all` (3) |
| `pua_protection` | `-PUAProtection` | `off` (0), `on` (1), `audit` (2) |
| `cloud_block_level` | `-CloudBlockLevel` | `default` (0), `moderate` (1), `high` (2), `high_plus` (4), `zero_tolerance` (6) |

The handler follows `FirewallProfileHandler`: `Get` reads `Get-MpPreference` (via the `PowerShell` func) and reports which named fields differ; `Set` issues one `Set-MpPreference` with only the named fields. Revert-on-removal (the M7 engine's contract) restores the values captured before first apply. **Tamper Protection can make `Set-MpPreference` silently not take effect**; `Set` therefore re-reads after writing and reports the setting non-compliant with detail "Defender did not accept the change — Tamper Protection may be on" rather than claiming success.

Server-side validation of the setting lives with the other kinds in `internal/protocol/profile.go`; the console's profile editor gains the kind.

## 4. Compliance rules (server, M12 engine)

| type | params | compliant when | unknown when |
|---|---|---|---|
| `defender_realtime` | — | Defender reports antivirus enabled and real-time protection on | no `defender` block |
| `defender_signatures_within` | `days` 1–30 | signature age ≤ `days` | no `defender` block or no age |
| `firewall_enabled` | `profiles`: subset of domain/private/public (default all three) | every named profile enabled | no `firewall` block, or a named profile absent |

The console's compliance rule editor gains the three types.

## 5. Console

Device detail gains a **Security** section: Defender mode, real-time protection, tamper protection, signature version and age, last scans; firewall on/off per profile. Unknowns shown as "not reported".

## 6. Testing

Protocol round-trip and backward compatibility (inventory without the new blocks parses; `defender` setting validation); collector functions tested against recorded WMI result structs (the query-to-struct mapping is a pure function, the WMI call is not run in tests); handler tests with a fake `PowerShell` covering get/set/revert, only-named-fields, and the Tamper Protection re-read; rule-engine table tests for the three rules; console tests. No on-machine application of any Defender or firewall setting. Reading real Defender/firewall status from this machine's installed agent is read-only and allowed if an agent is installed for verification.
