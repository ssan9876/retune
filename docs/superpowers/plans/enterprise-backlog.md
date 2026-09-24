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
| Maintenance windows | #25 |
| Phased rollouts | #26 |
| An OpenAPI document for the admin API | #27 |
| Server key rotation | #28 |
| Scheduled email reports | #29 |
| High availability guide, and CA creation safe for replicas starting together | #30 |
| Enterprise (802.1X) Wi-Fi: PEAP and EAP-TLS, not yet tried against a RADIUS server | #31 |
| Sign-in throttling shared across servers | #32 |
| Zero-touch provisioning: registration by serial, groups and names on enrollment, registered-only tokens, rename_computer | #33 |
| Windows Update reporting, install_updates, and max_missing_security_updates | #34 |
| Conditional access: compliance lookup API and signed device statements | #35 |
| Remote help: recorded remote PowerShell sessions, and commands delivered in seconds | #36 |

## To do, in order (round two)

The first list is done. These are the gaps an enterprise would still hit, limited to what can be built and verified from here.

| # | item | why an enterprise needs it | notes |
|---|---|---|---|
| 11 | **Roles beyond admin and read-only**: a helpdesk role | helpdesk staff unlock and troubleshoot, but shouldn't run code or change policy | done, #23 |
| 12 | **Two-person approval** for wipes, and for scripts or apps assigned to large groups | one compromised or careless account can't hit the whole fleet | done, #24 |
| 13 | **Maintenance windows**: scripts, apps and updates run only inside them | changes land out of hours | done, #25 |
| 14 | **Phased rollouts**: an assignment reaches a percentage of its group first, then widens | a bad deployment hits a few machines, not all | done, #26 |
| 15 | **An OpenAPI document for the admin API**, checked against the routes | integrations are built from a contract | done, #27 |
| 16 | **Server key rotation**: re-seal every stored secret under a new `secret.key` | a key suspected of exposure can be retired | done, #28 |
| 17 | **Scheduled reports by email**: compliance and inventory CSVs | auditors and managers get the numbers without a console account | done, #29 |
| 18 | **High availability guide**: two replicas, shared storage, what is already safe | no single point of failure | done, #30 |
| 19 | **Enterprise (802.1X) Wi-Fi** | most corporate networks | done, #31; needs a check against a real RADIUS server |

## To do, in order (round three: the Intune-style gaps)

Round two is done. These close the larger gaps between Retune and Intune, as far as they can be built and checked from here. Where Microsoft's own service is the real thing (Autopilot, Entra ID conditional access), the item is the Retune-native equivalent, and says so.

| # | item | why | notes |
|---|---|---|---|
| 20 | **Sign-in throttling shared across servers** | with several replicas, failed-password limits apply per replica today | done, #32 |
| 21 | **Zero-touch provisioning**: devices pre-registered by serial number, enrolled with a name and groups decided in advance, from a one-line install | Autopilot's job: a new laptop arrives, is unboxed, and configures itself | done, #33 |
| 22 | **Windows Update reporting and install-now**: which updates each device is missing, when it last installed, and a command to install now | update rings set policy; admins also need to see and act on the result | done, #34 |
| 23 | **Device compliance for conditional access**: an API network access control and identity providers can ask "is this device compliant?", and a signed compliance statement a device can present | conditional access: only compliant devices reach company resources | done, #35 |
| 24 | **Remote help**: an interactive PowerShell session to a device from the console, recorded | helpdesk fixes a machine without walking to it | done, #36; the shell, not a remote desktop |
| 25 | **A macOS agent**: enrollment, inventory, scripts and commands on macOS | most fleets aren't only Windows | checked in CI on a macOS runner; configuration profiles stay Windows-only |
| 26 | **Multi-tenant administration**: several organisations on one server, each seeing only its own | managed service providers | the schema already carries a tenant on every row |

## Can't be done from here

- **Autopilot and Entra ID conditional access themselves:** both need Microsoft's services; items 21 and 23 are the Retune-native equivalents.
- **iOS and Android:** managing them needs Apple's push certificates and MDM enrollment, and Google's Android Enterprise enrollment - both vendor programmes.
- **Authenticode signing of the MSI and agent:** needs a code-signing certificate, which is a purchase.
- **Checking wipe, BitLocker, update rings and network profiles on a real machine:** needs a disposable Windows VM.
- **macOS and Linux agents; multi-tenant administration:** these are product decisions, listed in `drafts/deferred.md`.
