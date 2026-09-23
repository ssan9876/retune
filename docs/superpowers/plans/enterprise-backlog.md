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

## To do, in order

| # | item | why an enterprise needs it | notes |
|---|---|---|---|
| 2 | **Authenticator hardening**: refuse a replayed TOTP code, encrypt TOTP secrets at rest | leftovers from the security review | in progress |
| 3 | **Uploaded line-of-business apps**: MSI/EXE packages, detection rules, supersedence | most enterprise software isn't in winget | draft: `drafts/app-packages-spec.md` |
| 4 | **Windows Update rings**: deadlines, pause, target release, patch compliance | patching on a schedule is table stakes | draft: `drafts/update-rings-spec.md`; applying needs a VM to verify |
| 5 | **Remote actions**: lock, collect logs, local admin password rotation (LAPS-style), wipe | lost or stolen devices, helpdesk support | draft: `drafts/remote-actions-spec.md`; built against fakes, needs a VM to verify |
| 6 | **Signed command payloads**: scripts and wipes signed by an operations key the agent trusts | a compromised server can't run arbitrary code | draft: `drafts/signed-commands-spec.md` |
| 7 | **Certificate, Wi-Fi and VPN profiles** | network access on managed devices | draft: `drafts/network-profiles-spec.md` |
| 8 | **SSO group → scope mapping**: an identity-provider group can grant a device-group scope | scoped admins managed where the users are | builds on M16 and M18 |
| 9 | **File settings refuse junctions** | the last low finding from the security review | agent |
| 10 | **Scale**: a fleet simulator for load testing, plus a documented sizing guide | knowing how many devices one server handles | needs a target fleet size from the user to be meaningful |

## Can't be done from here

- **Conditional access and Autopilot:** both need Microsoft's services.
- **Authenticode signing of the MSI and agent:** needs a code-signing certificate, which is a purchase.
- **Checking wipe, BitLocker, update rings and network profiles on a real machine:** needs a disposable Windows VM.
- **macOS and Linux agents; multi-tenant administration:** these are product decisions, listed in `drafts/deferred.md`.
