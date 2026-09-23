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
| A fleet simulator and a sizing guide | #22 |
| A helpdesk role | #23 |
| Two-person approval | #24 |

## To do, in order (round two)

The first list is done. These are the gaps an enterprise would still hit, limited to what can be built and verified from here.

| # | item | why an enterprise needs it | notes |
|---|---|---|---|
| 11 | **Roles beyond admin and read-only**: a helpdesk role | helpdesk staff unlock and troubleshoot, but shouldn't run code or change policy | done, #23 |
| 12 | **Two-person approval** for wipes, and for scripts or apps assigned to large groups | one compromised or careless account can't hit the whole fleet | done, #24 |
| 13 | **Maintenance windows**: scripts, apps and updates run only inside them | changes land out of hours | agent-side scheduling |
| 14 | **Phased rollouts**: an assignment reaches a percentage of its group first, then widens | a bad deployment hits a few machines, not all | |
| 15 | **An OpenAPI document for the admin API**, checked against the routes | integrations are built from a contract | |
| 16 | **Server key rotation**: re-seal every stored secret under a new `secret.key` | a key suspected of exposure can be retired | |
| 17 | **Scheduled reports by email**: compliance and inventory CSVs | auditors and managers get the numbers without a console account | |
| 18 | **High availability guide**: two replicas, shared storage, what is already safe | no single point of failure | docs, plus a check that shared state is |
| 19 | **Enterprise (802.1X) Wi-Fi** | most corporate networks | needs a VM and a RADIUS server to verify |

## Can't be done from here

- **Conditional access and Autopilot:** both need Microsoft's services.
- **Authenticode signing of the MSI and agent:** needs a code-signing certificate, which is a purchase.
- **Checking wipe, BitLocker, update rings and network profiles on a real machine:** needs a disposable Windows VM.
- **macOS and Linux agents; multi-tenant administration:** these are product decisions, listed in `drafts/deferred.md`.
