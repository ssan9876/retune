# M18 — Administrators limited to some device groups

Status: built on 2026-09-23 under the user's instruction to "make this as enterprise ready as we can". It was promoted from `docs/superpowers/drafts/sso-scoped-admins-spec.md` §3, whose SSO half shipped as M16. Builds on M1–M17.

## What and why

Every admin saw and managed the whole fleet, so a helpdesk at one site couldn't be given that site alone. An admin can now be scoped to device groups.

## Model

- **Storage:** `admin_scopes(admin_id, group_id)` holds the groups. `admins.scoped` records whether the admin is limited at all.
  - It's a separate column, not "has rows", so deleting an admin's last group leaves them seeing nothing rather than everything.
  - An admin with `scoped = false` sees the whole fleet.
- **Reading the scope:** it's read on every request, so narrowing an admin applies at their next click. An API token acts with its maker's current scope.
- **The last fleet admin:** the last enabled, unscoped admin can be neither scoped nor disabled.

## What a scoped admin can do

| | scoped admin |
|---|---|
| **Their devices only:** device list, export, device pages, software, recovery keys (list and reveal), retire and unenroll, commands (list, queue, get), item and setting statuses, run and install history, compliance results and counts, the dashboard | yes |
| **A device outside the scope** | 404, the same answer as a device that doesn't exist, so IDs can't be probed |
| **Queuing a command that names any device outside the scope** | refused, and nothing is queued |
| **Groups** | lists and reads only their own |
| **Item definitions** (scripts, profiles, apps, agent versions, policies) | read; assign to their own groups only; can't create, change or delete them |
| **Fleet concerns:** creating or changing groups, enrollment tokens, alerting, the audit log, admins, API tokens | refused (403 `scoped`) |

## Enforcement

- **Guards:** every route is registered through one of four wrappers, which together cover three questions:
  - is the admin role needed?
  - are API tokens refused?
  - are scoped admins refused?

  Registering a route without a wrapper is a startup panic.
- **Route test:** `routes_test.go` holds the expected class of every route, and fails on a route that isn't listed.
- **Queries:** device-level store queries take a `DeviceScope` (nil is the whole fleet) and filter on group membership in SQL. Single devices are checked with `DeviceInScope`.

## Console

- **Admins page:** shows each admin's devices, and an unscoped admin can limit another admin to groups.
- **Navigation:** a scoped admin's navigation leaves out the fleet pages.

## Not in this milestone

- **Mapping identity-provider groups to scopes.** Scopes are set in Retune.
- **Scoped enrollment tokens.** Scoped admins can't mint tokens, and new devices land in "All devices".
