# Drafts

Specs and plans written unattended on the night of 2026-09-14 ("please work on all of this while i go to bed"). None of them is approved, and none is scheduled yet. They sat in the gitignored `.superpowers/` folder until 2026-09-22 and were moved here so they are versioned and backed up.

**Numbering.** Inside the files, drafts call themselves M13–M20 and refer to each other by those numbers. `master` has since used M13 for Alerting, so those numbers are stale. The file names use topics instead, and a draft gets its real milestone number when it is promoted to `specs/` and `plans/`.

**Rulings.** Every design decision taken without the user is recorded in [`overnight-rulings.md`](overnight-rulings.md), with what it costs if it turns out wrong. Each one needs a yes before its milestone starts. The lock-id reservations in that file are out of date: `5274005` now belongs to `alerts.evaluate`.

| draft | overnight no. | what it adds | rulings that most need a decision | blocked on |
|---|---|---|---|---|
| [remote-actions](remote-actions-spec.md) | M13 | lock, collect logs, local admin password rotation, wipe | Retune-managed passwords rather than Windows LAPS; wipe through `MDM_RemoteWipe` | a disposable Windows VM: none of these may run on a real machine |
| [network-profiles](network-profiles-spec.md) | M16 | certificate, Wi-Fi and VPN profile settings | public certificates only (no client certificates, so no EAP-TLS); the first secrets stored inside profile settings | a VM to apply them on |
| [sso-scoped-admins](sso-scoped-admins-spec.md) | M17 | OIDC sign-in and admins scoped to groups | two new dependencies (`go-oidc`, `x/oauth2`); just-in-time provisioning from the groups claim; local login kept as a break-glass | an identity provider to test against |
| [signed-commands](signed-commands-spec.md) | M18 | scripts and wipes signed by an operations key the agent trusts | enforcement fixed at agent build time; profiles, apps and other commands left unsigned | nothing |
| [app-packages](app-packages-spec.md) | M19 | uploaded MSI/EXE packages, detection rules, supersedence | admin supplies the MSI product code; Retune never reboots on its own; packages not release-signed | a VM to install on |
| [update-rings](update-rings-spec.md) | M20 | Windows Update deadlines, pause, target release, patch compliance | rings are profiles with a `windows_update` setting, not a separate page | a VM: update policy must not change on a real machine |

Three drafts from that night are not here:
- **Alerts, metrics and retention (overnight M14).** Alerts shipped differently, as M13. Metrics and retention became [`specs/2026-09-22-m14-metrics-retention-design.md`](../specs/2026-09-22-m14-metrics-retention-design.md).
- **Cleanup plan.** Done, in PR #1.
- **Defender and firewall (overnight M15).** Promoted and built as M15: [`specs/2026-09-22-m15-defender-firewall-design.md`](../specs/2026-09-22-m15-defender-firewall-design.md). The draft files stay here for the record.

[`deferred.md`](deferred.md) lists what cannot be built without something from the user: hardware, a purchase, or a product decision.
