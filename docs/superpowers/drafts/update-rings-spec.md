# M20 — Windows Update rings: deadlines, pause, target release, patch compliance

Status: self-approved overnight under the user's standing directive; decisions ledgered for morning review. Builds on M1–M19 (extends M8's `windows_update` setting and M12's rule engine). **No update policy is changed on this machine** (standing rule) — handler changes are tested through the registry translation with fakes.

## 1. What and why

M8's `windows_update` setting can defer quality and feature updates, set active hours and control automatic restart, by writing the Windows Update for Business policy registry values. What is missing for real update rings — a pilot ring that gets updates first, a broad ring a week later — is the ability to force installation by a deadline, to pause a ring when an update goes bad, and to hold a ring on a specific Windows feature release; and a way to see whether devices are actually patched.

A **ring** in Retune is a configuration profile containing one `windows_update` setting, assigned to a group — the assignment engine already provides this. The milestone therefore extends the setting and adds compliance rules; it does not add a new object type.

## 2. Setting additions (all optional, validated server-side)

| field | range | registry values under `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate` |
|---|---|---|
| `quality_deadline_days` | 0–30 | `SetComplianceDeadline`=1, `ConfigureDeadlineForQualityUpdates`=n |
| `feature_deadline_days` | 0–30 | `SetComplianceDeadline`=1, `ConfigureDeadlineForFeatureUpdates`=n |
| `deadline_grace_days` | 0–7 | `ConfigureDeadlineGracePeriod`=n (and `ConfigureDeadlineGracePeriodForFeatureUpdates`=n) |
| `pause_quality_until` | a date ≤ 35 days after it is set | `PauseQualityUpdates`=1, `PauseQualityUpdatesStartTime`=<start date> |
| `pause_feature_until` | a date ≤ 35 days after it is set | `PauseFeatureUpdates`=1, `PauseFeatureUpdatesStartTime`=<start date> |
| `target_release` | `{product: "Windows 11", version: "24H2"}` | `TargetReleaseVersion`=1, `ProductVersion`, `TargetReleaseVersionInfo` |

Pauses are time-boxed by Windows itself (35 days); the server refuses a pause-until beyond that, and the console shows when it lapses. The translation stays in `UpdatePolicyValues` (M8's single translation point), so revert-on-removal keeps working through the registry handler.

## 3. Compliance rules (M12 engine)

| type | params | compliant when | unknown when |
|---|---|---|---|
| `os_build_min_per_release` | map of feature release base build → minimum full build, e.g. `{"26100": "26100.2605", "22631": "22631.4751"}` | the device's full build is ≥ the minimum listed for its base build | the base build is not in the map, or no build reported |
| `update_deadline_met` | `days` 1–60 | an update was installed within `days` (uses inventory `last_update_installed_at`) | no date reported |

`os_build_min_per_release` is how an administrator says "patched to at least this month's cumulative update" across a fleet on several Windows versions. Keeping the table current is the administrator's job; Retune does not fetch Microsoft's release information (no outbound calls to Microsoft).

## 4. Console

The profile editor's Windows Update form gains the new fields (deadline sliders, pause with a date picker bounded to 35 days, target release selects). The compliance rule editor gains the two rules, with a small table editor for the per-release minimums.

## 5. Testing

Validation (bounds, pause window, target release shape); `UpdatePolicyValues` translation golden tests for every new field and their combinations; revert via the existing registry handler with a fake; rule-engine tables for both rules; console tests. No update policy is applied to this machine.
