# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Dedicated endpoint and desktop engineers at larger organisations, who live in the console through the working day: enrolling and provisioning machines, deploying scripts, profiles, apps and agent builds to groups, watching compliance, and investigating individual devices. Helpdesk staff use it for tier-1 tasks (lock, restart, refresh inventory, collect logs, rotate or reveal a local admin password or BitLocker recovery key with a reason). Read-only users look without changing anything. Access can be limited to device groups.

## Product Purpose

Retune manages Windows machines (and, with fewer capabilities, Macs and a preview Linux agent) from a server the organisation runs itself, on-prem or in its own cloud. One server binary serves the agent API, the admin API and the console; a small Go agent on each machine enrolls with a one-time token and checks in over mutual TLS. Success is a fleet that is enrolled, inventoried, configured, patched and compliant without a round trip through anyone else's service.

## Positioning

- Self-hosted, with no dependency on Microsoft's cloud: its zero-touch provisioning is an Autopilot equivalent that does not need Microsoft's service.
- Open and inexpensive compared with per-device-licensed suites such as Intune.

## Operating Context

- Long daily sessions at a desktop, often next to other admin tools; the device list, device detail, commands and deployments are the working core.
- Fleets from dozens to tens of thousands of devices (measured to about 200 check-ins a second on a 2 vCPU server), so lists, filters, counts and status must stay dense and scannable.
- Consequential actions exist: wipes, scripts across many devices, secret reveals. They carry confirmation, reasons, audit, optional two-person approval and operations-key signatures.
- The console is also reached through the Admin API and API tokens; it is not the only client.

## Capabilities and Constraints

- Areas: Overview dashboard, Devices and device detail, Commands, Remote shell, Groups and assignments, Scripts, Profiles, Apps, Compliance, Alerts, Maintenance windows, Reports and CSV export, Enrollment tokens, Provisioning, Agent versions (per-platform builds, release import, staged rollout), Server update, Approvals, Admins, API tokens, Audit log.
- Roles: admin, helpdesk, read-only; any role can be limited to device groups.
- Stack: React 19 + TypeScript + Vite, react-router, plain CSS per component and page with shared tokens (`web/src/styles/tokens.css`, `base.css`); the build is embedded in the Go server binary.
- Terminology in use: device, enrollment token, group (static or dynamic), assignment (include/exclude), profile, script deployment, app, compliance policy, maintenance window, agent version, approval, stale (active but not seen recently), retired.
- Light and dark themes are both in use.

## Brand Commitments

The product name is Retune. No other binding brand, logo or typography commitments have been stated.

## Evidence on Hand

No customers, testimonials, benchmarks or pricing exist to cite. Measured sizing figures live in `docs/sizing.md`.

## Product Principles

1. Safe by default: consequential actions are deliberate, explained, reversible where possible, and on the record.
2. Density serves the engineer: a large fleet must stay scannable at a glance.
3. The organisation owns its fleet: nothing depends on a vendor's cloud.
4. Say plainly what happened and why, especially when something failed.
