# Enterprise backlog

The working list for making Retune usable by an enterprise, started on 2026-09-23 at the user's request ("continue creating a task list of features to make this app enterprise usable and continue to work on each one"). It's worked top to bottom, one PR per item, each merged once CI passes. The status column is updated as items land.

## Done

| item | PR |
|---|---|
| Defender and firewall status, policy, compliance (M15) | #5 |
| Single sign-on with OpenID Connect (M16) | #7 |
| API tokens for scripts and integrations (M17) | #8 |
| Security hardening from a full review | #9 |
| Admins limited to some device groups (M18) | #10 |
| Audit log streaming to a SIEM, filters, CSV export | #11 |
| Authenticator hardening: one use per TOTP code, secrets sealed at rest | #12 |
| Uploaded MSI/EXE apps with detection rules and in-app upgrades | #13 |
| Windows Update rings: deadlines, pauses, target release, patch compliance | #14 |
| Remote actions: lock, collect logs, wipe | #15 |
| Local admin password rotation, escrowed before it is set | #16 |
| Signed scripts and wipes: an offline operations key the agent requires | #17 |
| Trusted certificate profiles | #18 |
| SSO groups decide which devices an admin manages | #19 |
| File settings refuse to go through a junction or symlink | #20 |
| Wi-Fi networks and VPN connections, passphrases sealed | #21 |

## To do, in order

| # | item | why an enterprise needs it | notes |
|---|---|---|---|
| 10 | **Scale**: a fleet simulator for load testing, plus a documented sizing guide | knowing how many devices one server handles | in progress; measured without a target fleet size — docs/sizing.md gives the curve |

## Can't be done from here

- **Conditional access and Autopilot:** both need Microsoft's services.
- **Authenticode signing of the MSI and agent:** needs a code-signing certificate, which is a purchase.
- **Checking wipe, BitLocker, update rings and network profiles on a real machine:** needs a disposable Windows VM.
- **macOS and Linux agents; multi-tenant administration:** these are product decisions, listed in `drafts/deferred.md`.
