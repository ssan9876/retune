# Retune

Endpoint management for Windows machines, self-hosted on-prem or in the cloud.
One server binary serves the agent API, the admin API and the console; a small
Go agent runs on each machine.

## What works today

- **Enrollment.** A one-time token enrolls a machine; the server issues it a
  client certificate and the agent checks in over mutual TLS.
- **Inventory.** Hardware, operating system, disks, network adapters, installed
  software, local accounts, Microsoft Defender's status and the firewall's,
  refreshed daily or on demand.
- **Commands.** Run a PowerShell script, restart a machine, or refresh its
  inventory, with results (exit code and output) reported back.
- **Lifecycle.** Certificates renew before expiry; retiring a device stops its
  check-ins; unenrolling makes the agent delete its own identity and state.
- **Console and admin API.** Sign-in with single sign-on (OpenID Connect), or a
  password and optional authenticator
  codes, roles (admin, helpdesk and read-only), enrollment tokens, and an audit log.
- **Groups and assignments.** Static groups, or dynamic groups defined by a
  rule over inventory; items assigned to groups with include and exclude.
- **Script deployments.** A versioned PowerShell library assigned to groups,
  scheduled by the agent, with optional detect-and-remediate pairs.
- **Configuration profiles.** A versioned statement of how a machine should be
  — registry values, services, local group members and files — that the agent
  keeps true, with conflict detection and optional revert.
- **Application deployment.** winget packages assigned to groups, installed by
  the agent and removed on request, with per-device history.
- **Agent self-update.** Agent builds assigned to groups, verified by hash,
  swapped under supervision, and rolled back automatically if the new build
  cannot check in.
- **Maintenance windows.** Script deployments, app installs and agent updates
  held until a window assigned to the device opens, in its local time.
- **Compliance.** Policies assigned to groups that say what a healthy device
  looks like — encryption, patch level, check-in recency, forbidden or
  required software and more — evaluated server-side from what is already
  reported, with no agent involvement.
- **Alerts.** Rules over the same conditions the dashboard counts, delivered
  to email or a webhook, deduplicated so a fleet-wide fault is one message.
- **Overview dashboard and CSV export.** A fleet-wide landing page, and CSV
  export of the device list and of one policy's results, on demand or emailed
  on a schedule.
- **Metrics and retention.** A Prometheus endpoint over fleet state and the
  server's own background jobs, and history pruned after a horizon you set.
- **Packaging.** A container image and Compose stack for the server, and an MSI
  that installs the agent as a Windows service which enrolls itself.

## Requirements

- Go 1.27 and Node 20+ to build
- PostgreSQL 17
- Docker, to run the tests (they start a throwaway database)

## Build

```bash
npm --prefix web ci          # once
npm --prefix web run build   # builds the console into the server package
go build -o bin/ ./cmd/...
```

`make build` does the same on Linux and macOS.

## Run a server

Configure it with environment variables or a `retune-server.yaml` file
(`RETUNE_CONFIG` names another path). The environment wins over the file.

```yaml
database_url: postgres://retune:retune@127.0.0.1:5432/retune?sslmode=disable
public_url: https://mdm.example.com
agent_api_listen: :8443
data_dir: ./data
session_ttl_hours: 12
```

| Setting | Default | Meaning |
|---|---|---|
| `database_url` | — | PostgreSQL connection string (required) |
| `public_url` | — | the https address agents use (required) |
| `agent_api_listen` | `:8443` | the one listener; the admin API and console share it |
| `tls_mode` | `self-signed` | `self-signed`, `provided`, or `behind-proxy` |
| `tls_cert_file`, `tls_key_file` | — | required by `tls_mode: provided` |
| `client_cert_header` | `X-Forwarded-Client-Cert` | where `behind-proxy` reads the device certificate |
| `trusted_proxies` | — | IPs and CIDRs allowed to send that header; required by `behind-proxy` |
| `ca_key_source` | `file` | `file`, or `env` to read `CA_CERT_PEM` and `CA_KEY_PEM` |
| `data_dir` | `data` | holds the CA |
| `checkin_interval_seconds` | `300` | how often agents check in (minimum 30) |
| `session_ttl_hours` | `12` | how long an idle console session lasts (1–168) |
| `session_max_hours` | `24` | how long any session lasts, however busy, from sign-in (1–720; never shorter than `session_ttl_hours`) |
| `sweep_interval_seconds` | `300` | how often expired commands and sessions are cleared (minimum 10) |
| `agent_release_keys` | — | comma-separated public keys that sign agent builds; uploads are refused until set |
| `operations_keys` | — | comma-separated operations keys; when set, scripts, apps, profiles and wipes without a valid signature are refused at once (see [Signed scripts, apps, profiles and wipes](#signed-scripts-apps-profiles-and-wipes)) |
| `approvals_required` | `false` | hold wipes, and code sent to many devices, for a second administrator (see [Two-person approval](#two-person-approval)) |
| `approval_device_threshold` | `50` | how many devices a script, app or ad-hoc PowerShell may reach without approval |
| `smtp_host`, `smtp_port` | — / `587` | the relay alert email is sent through |
| `smtp_from` | — | the address alert email comes from; required with `smtp_host` |
| `smtp_username`, `smtp_password` | — | credentials for that relay, if it wants them |
| `smtp_starttls` | `true` | upgrade before authenticating; off only for a relay that does not offer it |
| `metrics_token` | — | turns on `GET /metrics` and is the bearer token a scraper sends; at least 32 characters |
| `agent_download_url` | this project's latest release | where the Enrollment page links for the agent installers: a GitHub `…/releases/latest` page, or a folder of your own holding the release files under their released names |
| `audit_retention_days` | `365` | how long audit entries are kept; `0` keeps them forever |
| `command_retention_days` | `90` | how long finished commands and their output are kept; `0` keeps them forever |
| `script_run_retention_days` | `90` | how long script run history is kept; `0` keeps it forever |
| `app_install_retention_days` | `90` | how long app install history is kept; `0` keeps it forever |
| `audit_syslog_address` | — | send the audit log to a syslog server: `udp://`, `tcp://` or `tls://host:port` |
| `audit_webhook_url` | — | send the audit log to an HTTPS endpoint as newline-delimited JSON |
| `audit_webhook_header` | — | one header sent with each webhook post, as `Name: value`, e.g. an `Authorization` header |
| `oidc_issuer`, `oidc_client_id`, `oidc_client_secret` | — | turn on single sign-on; all three or none |
| `oidc_admin_groups`, `oidc_helpdesk_groups`, `oidc_readonly_groups` | — | comma-separated group names that grant each role |
| `oidc_scope_groups` | — | identity-provider groups mapped to the device groups their members manage, as `group=Device group;other=Another` |
| `oidc_fleet_groups` | — | with `oidc_scope_groups`, the identity-provider groups whose members manage the whole fleet |
| `oidc_groups_claim` | `groups` | the ID token claim that lists a person's groups |
| `oidc_display_name` | `Sign in with SSO` | the sign-in button's text |
| `oidc_disable_local_login` | `false` | refuse password sign-in, leaving SSO the only way in |

Every setting is also an environment variable of the same name in capitals,
and the environment wins over the file.

```bash
./bin/retune-server migrate
./bin/retune-server bootstrap-admin --email you@example.com   # prints a password
./bin/retune-server serve
```

Open `https://<public_url>/` and sign in. With `tls_mode: self-signed` the
server issues its own certificate; agents pin it with the fingerprint from
`retune-server ca fingerprint`.

## Deploy with Docker

```bash
cd deploy/docker
cp .env.example .env        # set POSTGRES_PASSWORD and PUBLIC_URL
docker compose up --build -d
docker compose exec server /retune-server bootstrap-admin --email you@example.com
```

That builds the image from source. To run a released image instead, put
`image: ghcr.io/ssan9876/retune-server:<version>` on the `server` service and
start it with `docker compose up -d --no-build`.

The stack is the server plus PostgreSQL. Migrations run at startup, so there is
no separate migrate step. The `ca` volume holds the internal certificate
authority and the key that protects escrowed BitLocker recovery keys: **losing
it orphans every enrolled device and makes every escrowed recovery key
unreadable**, so back it up.

### Behind a reverse proxy

Where a load balancer or reverse proxy terminates TLS, run with
`tls_mode: behind-proxy`. The server then serves plain HTTP and takes each
device's certificate from a header, which it verifies against its own CA — the
proxy delivers the bytes, it does not get to vouch for them. The header is
accepted only from `trusted_proxies`, and a request carrying it from anywhere
else is refused.

```yaml
tls_mode: behind-proxy
client_cert_header: X-Forwarded-Client-Cert
trusted_proxies: 10.0.0.0/8, 192.168.1.7
```

The server refuses to start in this mode without both settings, because it
would otherwise serve the agent API unauthenticated. The proxy needs the CA
certificate to validate client certificates: `retune-server ca cert > ca.crt`.

A working example is in `deploy/docker/docker-compose.proxy.yml` with
`nginx.conf` beside it. It expects three files in `deploy/docker/certs`: the CA
from `retune-server ca cert` as `retune-ca.crt`, and the certificate agents
will see as `proxy.crt` and `proxy.key`. Agents pin the proxy's certificate,
not the internal CA, because the proxy is what they are talking to.

```nginx
server {
    listen 443 ssl;
    ssl_certificate     /etc/ssl/mdm.example.com.crt;
    ssl_certificate_key /etc/ssl/mdm.example.com.key;

    ssl_client_certificate /etc/ssl/retune-ca.crt;  # retune-server ca cert
    ssl_verify_client optional;                     # /enroll has no certificate yet

    location / {
        proxy_pass http://retune:8443;
        proxy_set_header X-Forwarded-Client-Cert $ssl_client_escaped_cert;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

`X-Forwarded-For` tells the server who is really signing in: failed sign-ins
are limited per account (10 in 15 minutes) and per address (50 in 15 minutes,
across every account), and the address is also what the sessions list
shows. It is read only from `trusted_proxies`, right to left past any further
trusted proxies, so a client can't choose its own address by sending the
header itself. Without it, everyone behind the proxy shares one address and
one allowance.

Agents reaching a proxy with a publicly trusted certificate need no pin;
`--pin` and `SERVER_CERT_FINGERPRINT` are for self-signed servers.

## Single sign-on

The console can sign people in through any OpenID Connect provider — Entra
ID, Okta, Google, Keycloak and the like. Register Retune with the provider as
a web application using the authorization code flow, with this redirect URL
(the server also logs it at startup):

```
https://<PUBLIC_URL>/api/admin/v1/oidc/callback
```

```yaml
oidc_issuer: https://login.microsoftonline.com/<tenant-id>/v2.0
oidc_client_id: <application id>
oidc_client_secret: <client secret>
oidc_admin_groups: <group id or name>          # full control
oidc_helpdesk_groups: <group id or name>       # device actions, no code or policy
oidc_readonly_groups: <group id or name>       # may look, not change
```

The provider must put the person's groups in the ID token, in the claim
`oidc_groups_claim` names — in Entra ID that is "Add groups claim" on the
app registration, which sends group object IDs; in Keycloak, a group
membership mapper. Someone in an admin group is an admin, else someone in a
helpdesk group is helpdesk, else someone in a read-only group is read-only,
else they are refused and nothing is created.

**Accounts are created on first sign-in**, and the role is worked out again
every time someone signs in: move a person between groups at the provider
and it takes effect the next time they sign in; take them out of every group
and they are refused, and the sessions and API tokens they already had end
there. A demotion takes their API tokens down to the new role at once.
Somebody removed from the provider altogether simply never signs in again —
their open session lasts until it expires (`session_ttl_hours`), and their API
tokens until they expire, unless an admin disables the account here, which
always wins and stops both.

An SSO account is identified by the provider's own ID for the person, never
by email address, because not every provider checks that an address belongs
to whoever claims it. So an SSO sign-in whose email matches an existing
password account is **refused, not merged**: to move a person over, remove or
re-email their password account first. SSO accounts have no password or
authenticator here; the provider owns both, MFA included.

Password accounts keep working beside SSO, which is the way in if the
provider is ever down. `oidc_disable_local_login: true` turns them off;
`retune-server bootstrap-admin` still works from the command line, and unsetting
the option is the way back in.

## Roles

| Role | Can |
|---|---|
| **admin** | everything |
| **helpdesk** | read everything an admin can; lock, restart and refresh a device, collect its logs, rotate its built-in Administrator's password; reveal a BitLocker recovery key or a local admin password (signed in, with a reason) |
| **read-only** | read |

Helpdesk runs no code and changes no policy: no scripts or ad-hoc PowerShell,
no wipes, no retiring or unenrolling, and nothing that decides what devices
run — scripts, profiles, apps, policies, assignments, groups — nor enrollment
tokens, alerting, admins or API tokens. Any role can also be limited to some
device groups (below).

## Limiting an admin to some devices

An admin can be limited to device groups — a site's helpdesk to that site's
machines, say. On **Admins**, **Limit devices** picks the groups. A limited
admin sees and manages only the devices in them: the device list and every
device page, commands, recovery keys, deployment and compliance status, and a
dashboard counting their devices alone. A device outside their groups answers
exactly as a device that does not exist.

They can read scripts, profiles, apps and compliance policies and assign them
to their own groups, but not create or change them, and anything that concerns
the whole fleet — groups themselves, enrollment tokens, alerting, the audit log,
admins and API tokens — is refused. An API token acts with its maker's limits as
they are now. Retune never lets the last admin who can manage the whole fleet be
limited or disabled.

### From the identity provider

With single sign-on, the identity provider can decide this instead of the
console. Map its groups to Retune device groups, by name:

```
OIDC_SCOPE_GROUPS=helpdesk-emea=EMEA laptops;helpdesk-emea=EMEA kiosks;helpdesk-us=US laptops
OIDC_FLEET_GROUPS=it-admins
```

Pairs are separated by semicolons, since a device group's name may contain a
comma; repeat a group to give it several device groups. At every sign-in, an
SSO account's devices are set from the groups it is in now:

- in any `OIDC_FLEET_GROUPS` group: the whole fleet;
- otherwise, every device group its groups map to;
- in none of them: sign-in is refused, its open sessions end and its API
  tokens are revoked — never the whole fleet by default.

A change is written to the audit log as `admin.scope_changed`. A mapped device
group that doesn't exist is skipped and named there (`unknown_groups`), so a
typo narrows access rather than widening it. While the mapping is set, an SSO
account's devices can't be changed on **Admins**; accounts that sign in with a
password are still limited there as before. Like a role, a change at the
provider takes effect at the person's next sign-in.

## API tokens

Scripts and other systems — a ticketing system, a SIEM, a nightly report —
call the admin API with a token rather than a browser session. Create one under
**API tokens** (admins only), choose read-only, helpdesk or admin access — never
more than your own — and a lifetime of
up to a year, and copy it: only a hash is kept, so it is shown once.

```bash
curl -H "Authorization: Bearer rtk_…" https://mdm.example.com/api/admin/v1/devices
```

A token needs no CSRF header. It stops working when it expires, when it is
revoked, or when the admin who made it is disabled — so someone who leaves does
not leave working credentials behind — and it never has more access than that
admin has now: an admin demoted to helpdesk, at the console or by the identity
provider, holds only helpdesk tokens from then on. An SSO account refused at
sign-in, because it is no longer in any mapped group, has its tokens revoked.
The audit log records what each token did as `api-token:<name>`.

A few things stay with a person at the console, and a token is refused them:
managing admins and API tokens, and revealing a BitLocker recovery key. A token
that leaks can therefore neither make replacements for itself to outlive its
revocation nor read recovery keys out in bulk. Make one token per system, so
each can be revoked on its own.

### The API's contract

The whole admin API is described in an **OpenAPI 3.1** document:
[`docs/openapi.json`](docs/openapi.json), also served by every server at
`GET /api/admin/v1/openapi.json` with no sign-in. Load it into Swagger UI or
Postman, or generate a client from it. Each operation's `x-retune-access` says
who may call it (the same classes the server enforces), and `security` says
whether an API token will do or only a console session.

The document is generated from the routes the server registers and the Go
types its handlers encode and decode, and a test fails if a route is missing
from it or the committed copy is stale. After changing the API, regenerate it
with `go test ./internal/server/adminapi -run TestOpenAPIDocument -update-openapi`.

## Authenticator codes

An admin who signs in with a password can add an authenticator app (TOTP,
six digits, 30 seconds) from the console or with `retune-server admin totp
--email E --enable`. Codes from one step either side of the server's clock
are accepted, for drift. **Each code works once**: the server remembers the
latest step used, so a code someone saw being typed can't be used after it,
and neither can any older code.

The authenticator secret is sealed with the server key in
`DATA_DIR/secret.key` before it is stored, bound to its account, so a copy
of the database alone doesn't reveal it. Secrets stored in the clear by an
earlier version are sealed the first time the new version starts. Run
`admin totp --enable` where the server's `DATA_DIR` is (inside the container,
with Compose), or with `CA_KEY_SOURCE=env` and `SECRET_KEY` set as the
server has them: it won't create a key of its own.

## Health checks

Two unauthenticated endpoints answer the questions an orchestrator asks. A
load balancer cannot sign in, so neither needs a session; neither reveals
anything beyond whether the server is working.

| Endpoint | Answers | Fails when |
|---|---|---|
| `GET /healthz` | is this process alive? | never, while it can answer at all |
| `GET /readyz` | can it do any work? | the database is unreachable |

They are deliberately different questions. Restarting a server because its
database blinked turns a short outage into a longer one, so liveness never
consults the database. Readiness does, which is what keeps an instance that
started before its database out of rotation instead of serving errors.

The container image is distroless — no shell, no `curl` — so the Compose
healthcheck is the server binary probing itself:

```bash
retune-server healthcheck    # exits 0 when /readyz says ready
```

It reads `AGENT_API_LISTEN` and `TLS_MODE` from the same configuration the
server uses, dials loopback, and prints the server's own words on failure so
`docker inspect` says *why* rather than only that something is wrong.

## Metrics

`GET /metrics` serves Prometheus text format. It is off, and answers 404,
until `METRICS_TOKEN` is set; then every scrape must send
`Authorization: Bearer <token>`. A scraper cannot sign in to the console, so
the token is the endpoint's only protection: make it long and random, and
keep `/metrics` off a public proxy if nothing outside needs it.

```yaml
scrape_configs:
  - job_name: retune
    scheme: https
    authorization:
      credentials: <METRICS_TOKEN>
    static_configs:
      - targets: ["mdm.example.com:8443"]
```

| Series | Type | What it counts |
|---|---|---|
| `retune_devices{state}` | gauge | devices that are `active`, `stale` (active, unseen for 7 days) or `retired` |
| `retune_compliance_devices{state}` | gauge | active devices by overall compliance |
| `retune_failed_deployments{kind}` | gauge | active devices with a failed `script`, `app`, `profile` or `agent` deployment |
| `retune_commands_outstanding{status}` | gauge | commands still `queued`, `delivered` or `running` |
| `retune_alerts_firing{kind}` | gauge | subjects firing on enabled alert rules |
| `retune_sweeper_runs_total{job,result}` | counter | background job runs: `ok`, `error`, or `skipped` because another replica held the lock |
| `retune_sweeper_rows_total{job}` | counter | rows those jobs affected |
| `retune_sweeper_last_success_timestamp_seconds{job}` | gauge | when each job last succeeded |
| `retune_build_info{revision,go_version}` | gauge | always 1 |

The fleet gauges come from the database, so every replica reports the same
numbers. The `sweeper` series are per process and reset when it restarts.

Alerts watch the fleet; nothing inside Retune can tell you that the alert
job itself has stopped. That is the one rule worth adding in Prometheus:

```yaml
- alert: RetuneAlertsNotRunning
  expr: time() - max(retune_sweeper_last_success_timestamp_seconds{job="alerts.evaluate"}) > 900
```

## Retention

History is deleted once it is older than a horizon, measured in days:

| Setting | Default | Deletes |
|---|---|---|
| `AUDIT_RETENTION_DAYS` | 365 | audit entries |
| `COMMAND_RETENTION_DAYS` | 90 | finished commands and their output |
| `SCRIPT_RUN_RETENTION_DAYS` | 90 | script run history |
| `APP_INSTALL_RETENTION_DAYS` | 90 | app install history |

`0` keeps that history forever; anything else can be up to 3650.
**Retention is on by default, so if you need older history than this, raise
the setting before upgrading**: the first run after an upgrade deletes
everything past the horizon.

Only history is deleted. A command still waiting for its device is kept
however old it is, and nothing that says what a device is or should be —
inventory, statuses, compliance results, recovery keys, anything an admin
created — is ever deleted by age. Losing old run history does not change
what a device is told to do.

The pruning runs hourly, in batches of 5,000 rows, and stops after a million
rows per table per run, so the first run on a large, old database spreads
itself over a few hours rather than holding one long lock. Each run that
deletes anything leaves one `retention.pruned` entry in the audit log with
the counts. Alert delivery history is kept for 30 days and has no setting.

## The audit log

Everything an admin, an API token or the server itself changes is written to
the audit log. **Audit** in the console lists it newest first, filtered by
who, by action (both match part of the text, ignoring case) and by date, and
its **Export CSV** link (`GET /audit/export.csv` on the admin API, which takes
the listing's `actor`, `action`, `since` and `until` parameters) downloads
whatever the filters show, guarded against spreadsheet formulas like the other
exports.

### Sending it to a SIEM

Set either destination, or both, and the server copies each audit entry there:

- `AUDIT_SYSLOG_ADDRESS`, as `tls://siem.example.com:6514`, `tcp://…:514` or
  `udp://…:514`. Each entry is one RFC 5424 message, facility 13 (log audit),
  severity 5 (notice), app name `retune`, the action as the message ID and the
  entry as JSON for the text. TCP and TLS use octet-counted framing (RFC 6587);
  TLS checks the server's certificate against the system's trusted roots.
- `AUDIT_WEBHOOK_URL`, an `https://` URL that is posted batches of up to 500
  entries as newline-delimited JSON (`application/x-ndjson`), with
  `AUDIT_WEBHOOK_HEADER` sent alongside, e.g.
  `Authorization: Bearer <token>`. Anything but a 2xx answer fails the batch,
  and redirects aren't followed.

Each entry looks like:

```json
{"id":"0192…","at":"2026-09-22T10:00:00.123456Z","actor":"alice","action":"device.retired","target_kind":"device","target_id":"0191…","details":{"hostname":"PC-1"}}
```

Delivery is at least once and in order. Entries are sent every 30 seconds,
once they are two minutes old (an entry is stamped when its change begins, so
this leaves time for a slow change to commit before later ones are sent). A
destination that is down is retried from the same place on the next run, and
the server records how far each destination has got, so a restart neither
loses nor repeats more than one batch; a receiver that must not see a
duplicate should key on `id`. A destination starts from when it is first
configured: to load earlier history into a SIEM, use the CSV export.

The destinations are server settings, not console ones, so an admin can't
quietly redirect the record of what admins do. The `audit.stream` sweeper job
on `/metrics` shows whether sending is working, and failures are logged.

## Sizing

What decides the size of the server is check-ins per second: devices divided
by the check-in interval (300 seconds by default). Measured on one 16-thread
desktop running the server, PostgreSQL and the load generator together, a
server answered check-ins in under 35 ms at the 99th percentile up to about
150 a second — a 45,000-device fleet at the default interval — and slowed,
without failing, past about 200. [docs/sizing.md](docs/sizing.md) has the
numbers, recommended machines by fleet size, and how to measure your own with
`retune-loadsim`.

## High availability

Two or more servers can run behind a load balancer against one PostgreSQL and
a shared `DATA_DIR`, with no sticky sessions. Background jobs, migrations,
alerts, reports and approvals are already safe to run on several at once.
[docs/high-availability.md](docs/high-availability.md) covers the layout, the
load balancer, what must be shared, what is still per server, and upgrades.
## Backups

Two things have to be backed up, and they have to be backed up together:

- **`DATA_DIR`** (the `ca` volume in Compose) holds `ca/ca.key` and
  `ca/ca.crt`, the `secret.key` that protects escrowed BitLocker recovery
  keys, authenticator secrets and alert webhook secrets, the uploaded
  agent builds in `agents/`, and uploaded app installers in `app-packages/`. Losing it orphans every enrolled device, makes
  every escrowed recovery key unreadable, locks out every admin who signs in
  with an authenticator code (until `retune-server admin totp --disable`), and
  leaves the database pointing at builds that are no longer there.
- **The PostgreSQL database**, which holds everything else.

```bash
docker compose exec -T db pg_dump -U retune retune | gzip > retune-$(date +%F).sql.gz
docker run --rm -v retune_ca:/data -v "$PWD:/backup" alpine \
    tar czf /backup/retune-data-$(date +%F).tar.gz -C /data .
```

To restore, put both back before starting the server:

```bash
docker compose down
docker volume rm retune_db retune_ca
docker volume create retune_db && docker volume create retune_ca
docker run --rm -v retune_ca:/data -v "$PWD:/backup" alpine \
    sh -c 'tar xzf /backup/retune-data-DATE.tar.gz -C /data && chown -R 65532:65532 /data'
docker compose up -d db
gunzip -c retune-DATE.sql.gz | docker compose exec -T db psql -U retune retune
docker compose up -d server
```

Migrations run at startup, so a dump from an older release is brought forward
on first boot. Restoring the database without `DATA_DIR` is not a restore: the
devices in it are authenticated by certificates only that CA can vouch for.

### Rotating the secret key

If `secret.key` may have been exposed — a backup that went astray, a server
that was compromised — retire it: stop every server, then

```bash
retune-server rotate-secret-key --dry-run   # proves the current key opens everything
retune-server rotate-secret-key
```

and start the servers again. Every authenticator secret, BitLocker recovery
key, local admin password, webhook secret and Wi-Fi or VPN passphrase is
decrypted with the old key and re-encrypted with a new one, in a single
transaction: either all of it moves or none does. The command refuses to run
while any server is connected to the database (each running server holds a
lock that says so), and changes nothing if a stored value doesn't open with
the key it was given.

The new key replaces `DATA_DIR/secret.key`; the old one is kept beside it as
`secret.key.old-<time>`. Copy the new key to every server and into your
backups, then destroy the old one and any backup that holds it. With
`CA_KEY_SOURCE=env`, pass `--out FILE`: the new key is written there, and you
set `SECRET_KEY` to it on every server before starting them. The rotation is
recorded in the audit log as `secret_key.rotated`.

Old database backups are still sealed under the old key, which is what makes
destroying it worthwhile, and also why a restore from before the rotation
needs the key from before it.

## Enroll a machine

Every [release](https://github.com/ssan9876/retune/releases/latest) carries
the agent for each platform, signed with the project's release key:

| File | For |
|---|---|
| `retune-agent.msi` | Windows (x64), installs the service |
| `retune-agent.exe` and `.sig` | Windows, the bare agent; upload both under **Agent versions** to update a fleet |
| `retune-agent.pkg` | macOS 13 or later, Apple silicon and Intel |
| `retune-agent-darwin-*` and `.sig` | macOS, the bare agent |
| `retune-agent-linux-amd64`, `-arm64` and `.sig` | Linux (preview: check-in only), with `retune-agent.service` |
| `retune-server-*`, `retune-sign-*` | the server and the signing tool, for running without Docker |
| `SHA256SUMS` | checksums of all of the above |

Create a token under **Enrollment** in the console: it shows the install
command for the token and links to the files.

A machine that enrolls with the same serial number or SMBIOS UUID as a device
already enrolled — usually the same machine, reimaged — becomes a new device,
and the enrollment's audit entry names the earlier one (`same_hardware_as`).
The earlier device is **not** retired automatically: the serial is the
enrolling machine's own claim, and retiring on it would let anyone holding an
enrollment token cut any machine off by quoting its serial. After a genuine
reimage the old record stops checking in and goes stale; retire it from its
page.

With the MSI, which installs the agent as an automatic service running as
LocalSystem:

```powershell
msiexec /i retune-agent.msi SERVER_URL=https://mdm.example.com ENROLL_TOKEN=<TOKEN> SERVER_CERT_FINGERPRINT=sha256:<FINGERPRINT> /qn
```

The installer writes the settings and the service enrolls on its first start,
retrying until the server is reachable, so an install does not fail because the
network was not ready. The token is removed from disk once it has been spent.

One caveat: if you install with verbose logging (`/l*v`), the enrollment token
appears in that log. Windows Installer records a deferred action's data
verbatim and ignores the package's request to hide it, so this cannot be fixed
from the installer. `msiexec` writes no log unless asked, and the token is
spent within seconds, but prefer `--max-uses 1` tokens and delete verbose logs.
To build the MSI yourself instead of downloading it, run
`pwsh deploy/msi/build.ps1` (or `make msi`), which needs the WiX 5 CLI:
`dotnet tool install --global wix`.

Or by hand, without the installer:

```powershell
retune-agent.exe enroll --server https://mdm.example.com --token <TOKEN> --pin <FINGERPRINT>
retune-agent.exe run
```

Create the token in the console under Enrollment, which also shows the matching
`msiexec` line.

The agent logs to `C:\ProgramData\Retune\logs\agent.log`, and sends warnings and
errors to the Windows Event Log under the source `Retune`.

Unenrolling a device from the console makes the agent delete its identity and
state, then stop and disable its own service. The MSI stays installed, so a new
token re-enrolls it:

```powershell
retune-agent.exe configure --server https://mdm.example.com --token <TOKEN>
Set-Service Retune -StartupType Automatic
Start-Service Retune
```

### On a Mac

The macOS agent (Apple silicon or Intel, macOS 13 or later) runs as a launchd
daemon, as root. `retune-agent.pkg` installs it to `/usr/local/bin` and, given
settings, enrolls the Mac and starts the daemon. A pkg cannot take
command-line properties the way an MSI does, so it reads a property list with
`ServerURL`, `EnrollToken` and (for a self-signed server)
`ServerCertFingerprint` from the first of:

1. `/Library/Managed Preferences/com.retune.agent.plist` — a configuration
   profile from your MDM with a custom settings payload for the domain
   `com.retune.agent`. This is the unattended path: push the profile, then
   the pkg.
2. `retune-agent.plist` in the same folder as the pkg — for installing by
   hand. **Copy macOS settings** on the Enrollment page gives you the file.
3. `/Library/Preferences/com.retune.agent.plist` — dropped by your own
   imaging. The pkg deletes it once used.

`deploy/macos/retune-agent.plist.example` (also in each release) shows the
format. Without settings the pkg installs the binary and nothing else. It
logs to `/var/log/retune-agent-install.log`, and installing a newer pkg over
an enrolled Mac just restarts the daemon on the new binary. A release is
code-signed and notarized only when the project has an Apple Developer ID;
an unsigned pkg installs through MDM or `sudo installer -pkg
retune-agent.pkg -target /`, but Gatekeeper refuses a double-click.

By hand, with the bare binary for the Mac's processor in
`/usr/local/bin/retune-agent`:

```bash
sudo retune-agent enroll --server https://mdm.example.com --token <TOKEN> --pin <FINGERPRINT>
sudo retune-agent install
```

`install` writes `/Library/LaunchDaemons/com.retune.agent.plist` and starts
the daemon; `uninstall` stops and removes it. The agent keeps its state in
`/Library/Application Support/Retune`, readable by root only, and logs to
`/var/log/retune-agent.log`.

A Mac reports its model, serial number, hardware UUID, macOS version,
processor, memory, startup volume (with FileVault in the BitLocker column),
network interfaces, applications (outside `/System`), local accounts, the
`admin` group and the application firewall — as all three firewall profiles,
so the firewall compliance rule works unchanged. Scripts run with PowerShell 7
(`pwsh`), so one script can target both platforms; install it on the Mac
first, or scripts fail saying it is missing. Restart works (`shutdown` counts
in whole minutes), and the remote shell is `zsh` as root.

Not on a Mac yet: configuration profiles, lock, wipe, local administrator
passwords, log collection, Windows Update reporting, app deployment, and
self-update — update the binary with your own tooling, then
`sudo launchctl kickstart -k system/com.retune.agent`. Each of those fails on
a Mac with a reason rather than silently. The device key is a file in the
root-only state directory, not in the Keychain.

### On Linux (preview)

The Linux agent is a preview: it enrolls and checks in, but reports only its
hostname and refuses scripts and restarts. Releases carry it so the
enrollment path can be tried on Linux; it has no installer. Copy `retune-agent-linux-amd64` (or `-arm64`) to
`/usr/local/bin/retune-agent`, then:

```bash
sudo retune-agent enroll --server https://mdm.example.com --token <TOKEN> --pin <FINGERPRINT>
sudo install -m 0644 retune-agent.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now retune-agent
```

### Zero-touch provisioning

Register devices by serial number before they arrive, and a new laptop
configures itself: on **Provisioning**, add them one at a time or import a CSV
from your supplier —

```csv
serial,name,groups,notes
PF3ABC12,SALES-01,Sales laptops;EMEA,Jo's replacement
PF3ABC13,SALES-02,Sales laptops
PF3ABC14
```

— the computer name, the static groups (by name, separated by semicolons)
and notes are optional. An import with any problem imports nothing and lists
every problem. When a registered device enrolls it joins its groups at once,
so its apps, scripts and profiles are waiting on its first check-in, and if it
was given a name it is renamed (`rename_computer`; the name takes effect when
it next restarts). A dynamic group can't be chosen: its rule decides who is in
it.

For the install itself, create an enrollment token with **Only devices
registered on the Provisioning page** ticked and put the `msiexec` line it
shows into your imaging, a provisioning package or your supplier's
pre-install. Such a token enrolls only registered serial numbers, so one that
leaks doesn't enroll strangers' machines. The serial is the device's own
claim, though, so it isn't a secret: treat the token as the credential it is.

A registration is used once: while the device it became is active, the same
serial doesn't match it again, so nobody quoting a known serial can enroll
more machines into its groups. To reimage a registered machine, retire its old
record first; the registration then applies to the machine enrolling anew.

This is Retune's equivalent of Windows Autopilot, which itself needs
Microsoft's service.

## Grouping devices

A group is either a list of devices you pick, or a rule evaluated over what the
agents report. Rules are re-evaluated when a device's inventory arrives, when it
enrols, and for every group every 15 minutes. "All devices" is built in.

```
ram_gb >= 16 AND hostname LIKE 'DESKTOP-%'
has_software('Google Chrome', '<', '120.0.0')
last_seen_days > 7 AND NOT model = 'Virtual Machine'
```

Conditions combine with `AND`, `OR`, `NOT` and parentheses. Text fields compare
with `=`, `!=` and `LIKE`; number fields with `=`, `!=`, `<`, `<=`, `>` and
`>=`. Keywords and field names ignore case; quoted values do not. Write a
literal quote by doubling it: `'it''s'`.

| Field | Type | Meaning |
|---|---|---|
| `hostname` | text | the machine's name |
| `os_version` | text | e.g. `Microsoft Windows 11 Pro` |
| `os_build` | text | the build number |
| `manufacturer`, `model`, `serial` | text | from the hardware inventory |
| `agent_version` | text | the version of the agent |
| `ram_gb` | number | installed memory, rounded |
| `last_seen_days` | number | whole days since the last check-in |

`has_software('name')` matches an installed package, ignoring case. With a
version — `has_software('name', '>=', '1.2.3')` — the comparison is numeric per
component, so `1.10.0` is correctly newer than `1.9.0`. A version that is not
made of dotted numbers takes part in no ordering comparison, though `=` and `!=`
still work on it.

A device that has never checked in matches no `last_seen_days` comparison.

Rules are parsed and compiled to parameterized SQL: field names come from a
fixed list and values are always bound, so a rule cannot reach a column it was
not granted or inject SQL. A rule may be at most 2000 characters and 20 levels
of nesting.

Items are assigned to groups as `include` or `exclude`, and **exclude always
wins** — if any group a device belongs to excludes an item, that device does not
get it, whatever else includes it.

### Phased rollouts

A script, app, configuration profile or agent build can be included in a
group **in phases**: to a percentage of the group first, widening on a
schedule — 10% now, then 20% more every 24 hours, say, reaching everyone four
days later. In the console, tick **Roll out in phases** when assigning; in the
API, send `"rollout": {"percent": 10, "step_percent": 20, "step_hours": 24}`
with the assignment. Leave the steps out (or at 0) and it stays at its
percentage until you change it.

Which devices go first is fixed per item: each device has a place from 0 to 99
worked out from its id and the item's, so the devices that have it keep it as
the rollout widens, and the same devices lead whichever group the item is
assigned through. A device reached in full through another group gets it
regardless.

To **pause** a rollout, assign it again with no steps at the percentage it has
reached; to **finish** it, assign it again at 100%; to **back out**, assign it
again lower, or remove the assignment. Assigning again restarts the schedule
from its new percentage. Each assignment shows how far it has got and when it
will reach the whole group. Exclusions, compliance policies and maintenance
windows are never phased.

## Deploying scripts

A **command** is a one-off: run this now, on these machines, once. A
**deployment** is a standing statement about a fleet — "every workstation
should have this" — that keeps applying as machines join a group, come back
online, or get a new version of the script.

Scripts live in a library under **Scripts**. Every edit to a body creates a new
immutable version, so a run always tells you exactly what ran; renaming or
re-describing a script does not. Assign one to a group and choose how it runs:

| Option | Default | Meaning |
|---|---|---|
| How often | once | `once` per version, or `recurring` |
| Every | 24 hours | the gap between recurring runs |
| Run as | the system account | or the signed-in user, in their own session |
| Timeout | 600 seconds | per execution, 1 to 86400 |
| Max retries | 2 | consecutive failures before the agent stops retrying that version |
| Rerun on new version | yes | whether a new version runs again where an older one already ran |

The agent decides when to run, from its own local state, so a machine that was
offline for a week comes back to one run rather than a week of missed ones. It
fetches each body once per version and caches it.

**Detection and remediation.** Give a script an optional detection script and it
becomes a pair. Detection runs first: exit 0 means there is nothing to do, and
the main script never runs. Any other exit code runs the main script and then
runs detection again — and that second detection decides whether the deployment
succeeded, because a remediation that finishes cleanly while leaving the machine
non-compliant has not actually fixed anything.

**Running as the signed-in user.** The agent runs as LocalSystem, so it takes
the console user's token and starts the script in their session, with their
environment and their profile. A machine with nobody signed in reports `pending`
with that reason and runs nothing; it runs as soon as somebody signs in, without
waiting for an administrator to do anything. Because the script is passed on the
command line rather than through a file the user could not read, a script run
this way is limited to 8 KiB.

Every run is kept, so you can see whether a script is flapping rather than only
its latest state. Deleting a script removes its assignments and keeps its runs.

## Applications

Apps live under **Apps**. An app is either a winget package — a package ID,
and optionally an exact version — or an installer you upload (below). Every
change to what gets installed creates a new immutable version; renaming or
re-describing an app does not.

Assign one to a group and choose what to do:

| Option | Default | Meaning |
|---|---|---|
| What to do | install | `install`, or `uninstall` to remove it |
| Timeout | 900 seconds | per winget invocation, 60 to 14400 |

While winget or the network is unavailable on a device, its apps keep their
last reported status rather than flipping to some new "unknown" state; the
agent log on that machine is where the failure actually shows.

**Removal is deliberate.** A device that drops out of a group keeps the
software. To take something away, assign the app with uninstall intent — so a
dynamic group whose rule stops matching never quietly wipes software off
machines.

Retune installs what is missing and then leaves it alone: it does not upgrade
an app when a newer release appears upstream. Moving a fleet to a new version
means pinning one, which is a deliberate act with a version number attached.
It does re-check about once an hour, and puts back anything that has been
uninstalled, because an app assigned to a group should be on the machines in
that group.

Installs run as the system account, machine-wide. There is no per-user scope:
the agent is LocalSystem, so a user-scope install would land in the system
account's profile rather than anyone's.

### Uploaded installers (MSI and EXE)

For software that isn't in winget, choose **An installer I upload** and pick
an `.msi` or `.exe` of up to 2 GiB. The server keeps it under
`DATA_DIR/app-packages`, named by its SHA-256; a device downloads it over its
own mutual-TLS connection only while the app is assigned to it, checks the
hash, runs it as SYSTEM, and deletes it afterwards.

| Setting | Meaning |
|---|---|
| Install arguments | an EXE's silent switches, such as `/S`, passed exactly as written; for an MSI, extra properties after `msiexec /i <file> /qn /norestart` |
| Uninstall command | the whole command line, environment variables expanded; optional for an MSI detected by product code, which is removed with `msiexec /x` |
| Success exit codes | default `0, 3010, 1641`; 3010 and 1641 are reported as succeeded, with a note that a restart is needed — Retune never restarts a machine itself |
| Detection | how a device tells the app is installed, before and after: an MSI product code (with an optional minimum `DisplayVersion`), a registry key or value under `HKEY_LOCAL_MACHINE` (either registry view; optionally equal to something, or at least a version), or a file (optionally with at least a version in its version resource) |
| Remove the previous version first | on an upgrade, uninstall the version this agent installed before running the new installer, for installers that can't upgrade in place |

Upload a new file to make a new version; devices whose detection rule no
longer matches install it. MSI major upgrades replace the old version on their
own; "remove the previous version first" is for the rest, and only ever
removes a version the agent itself installed. A device without App Installer
can still install uploaded packages.

Uploaded files no app version uses any more are deleted after a day. Include
`DATA_DIR/app-packages` in backups, or re-upload after a restore: a version
whose file is missing fails to install with "the server no longer has this
package".

## Maintenance windows

A **maintenance window** says when devices may be changed: on some days of the
week (or every day), from a time, for up to 24 hours — `Sat, Sun from 22:00
for 4 hours`, say. It is in each device's own local time, and may run past
midnight. Create windows on the **Maintenance windows** page and assign them
to groups like anything else.

A device with at least one window assigned makes these changes only while one
of them is open:

- script deployments;
- app installs and removals;
- agent updates.

Anything due outside a window waits for the next one. Commands you send (a
script run now, a restart, a lock, a wipe) are not held: they are somebody
asking for something now. Configuration profiles aren't either: they keep a
setting as it should be rather than making a change. A device with no window
assigned can be changed at any time, and excluding a window from a group lifts
it for those devices. If a device can't read a window assigned to it, it holds
everything back rather than guessing.

## Signed scripts, apps, profiles and wipes

Release signing means the server can't push an agent build nobody signed. It
can still run code on every machine, though: through a script or an ad-hoc
PowerShell command, through an app (an uploaded installer runs as SYSTEM, with
whatever arguments and uninstall command it is given), and through a profile
(which can add local administrators, write the registry and drop files). And
it can order a wipe. An organisation that wants all of those to need a second,
offline approval can build agents that **require an operations signature**:

1. Make an operations key, on a machine the server can't reach:
   `retune-sign keygen --out ops --name operations`.
2. Build the agent with its public key:
   `make agent … OPERATIONS_PUBKEYS=<the text of ops/operations.pub>` (or
   `build.ps1 -OperationsKeys …`). This is a build setting on purpose: nothing
   the server sends can turn it off. A key list that doesn't parse makes the
   agent refuse everything, not nothing.
3. Set `OPERATIONS_KEYS` on the server to the same public key. The server
   then refuses unsigned scripts, apps, profiles and wipes at once, rather
   than letting every device refuse them later, and the console asks for
   signatures.

Then:

- **A script** (deployed or ad hoc) runs only if
  `retune-sign sign-script --key operations.key [--detection detect.ps1] script.ps1`
  signed exactly its code, detection script included. Paste the output into the
  script editor or the Run script dialog. Renaming a signed script keeps its
  signature; changing its code needs a new one. Line endings don't matter, so
  a file saved in Notepad matches the same text pasted into the console.
- **A wipe** needs an order signed for that one device:
  `retune-sign sign-wipe --key operations.key --device <id> [--protected] --valid-for 4h`
  (at most 24 hours). Paste it into the Wipe dialog. The agent refuses an order
  for another device, one whose protected setting was changed, and one that
  has expired, by its own clock.

- **An app** is installed, detected or removed only if
  `retune-sign sign-app --key operations.key [--file setup.msi] app.json`
  signed exactly its definition: the winget package, pinned version and
  arguments, or for an uploaded package the file's SHA-256, its arguments,
  uninstall command, success exit codes and detection rule. `app.json` is the
  body the console sends; the app editor shows it, ready to save. With
  `--file`, the hash is read from the installer itself. A version installed
  with "remove the previous version first" also checks the previous version's
  signature before running its uninstall.
- **A profile** is applied only if
  `retune-sign sign-profile --key operations.key profile.json` signed exactly
  its settings, as devices receive them — so a Wi-Fi or VPN secret must be in
  `profile.json` in the clear, including one the editor keeps from the last
  version without showing it. A device that receives an unsigned profile
  version leaves the machine as it is: it neither applies it nor undoes the
  version before it, and reports each setting as refused.

For apps and profiles, as for scripts, renaming keeps the signature and
changing what it covers needs a new one. Signing an existing version makes a
new version, so devices fetch the signature with it. Versions created before
the keys were set are unsigned: agents that require signatures refuse them
until they are signed.

Everything else — lock, logs, password rotation — works as before: those run
through fixed, bounded handlers rather than arbitrary code.

## Two-person approval

Signing puts a second key between the server and the fleet. Two-person
approval puts a second person between one administrator and the fleet, with
nothing to build: set `APPROVALS_REQUIRED=true`, and these wait on the
**Approvals** page until another administrator approves them:

- **every wipe;**
- **ad-hoc PowerShell**, once the administrator sending it would have reached
  more devices than `APPROVAL_DEVICE_THRESHOLD` (50 unless set) within the
  last hour. It is counted per person, API tokens included, not per request,
  so a thousand devices can't be sent fifty at a time. Commands someone else
  already approved don't count;
- **assigning** a script, app, configuration profile or agent build to a
  static group of more devices than that, or to any dynamic group or All
  devices, which can grow to any size once approved. Excluding something, and
  assigning a compliance policy, which only reports, never wait;
- **a new version** of a script, app or profile whose assignments already
  reach more devices than that, or any dynamic group or All devices. The
  version is stored, secrets sealed, but devices keep the current one — and
  can't fetch the new one — until it is approved. Renaming, which changes no
  code, doesn't wait. Approving an older held version once a newer one is
  current fails, rather than rolling devices back;
- **adding a device to a static group** with something assigned to it, once
  the group would hold more devices than the threshold, and **changing the
  rule of a dynamic group** with something assigned to it. Otherwise an
  assignment approved for a small group could be grown to the whole fleet.

The request is checked in full when it is made — hostname, reason, signature,
that the device is still enrolled, that the rule parses — so nobody is asked
to approve something that could never run. It answers `202 Accepted` with the
held request rather than `201 Created`. Approving carries it out at once, as the person who asked:
the command or assignment is theirs in the audit log, and `approval.approved`
says who let it through. If it can no longer be done — the device was retired
in the meantime — the approval is marked `failed`, with why.

The rules:

- Nobody approves their own request, including one sent with an API token
  they made. They can withdraw it (reject it) instead.
- Approving and rejecting need an administrator of the whole fleet, signed in
  to the console: an API token can ask, but cannot decide.
- A request not decided within a day expires.

`GET /api/admin/v1/approvals?status=pending` lists what is waiting;
`POST /api/admin/v1/approvals/{id}/approve` and `…/reject` decide, with an
optional `{"reason": "…"}`.

## Updating the agent

Agent builds live under **Agent versions**. Upload a build, assign it to a
group, and the agents in that group replace themselves with it.

A build is stamped with its version at compile time and **signed with the release key**. `retune-sign keygen` makes the key once; keep `release.key` off the server — the server never needs it. `make agent VERSION=1.4.0 RELEASE_KEY=path/to/release.key RELEASE_PUBKEYS=<public key>` (or `deploy/msi/build.ps1 -ReleaseKey … -TrustedKeys …`) produces `retune-agent.exe` and `retune-agent.exe.sig`. Upload both. The server checks the signature against `AGENT_RELEASE_KEYS` before it accepts a build, and every agent checks it again after downloading, against the keys it was built to trust. An admin account cannot push code the key never signed; neither can the server.

An agent built without a version stamp or without a trust list refuses to self-update and says so.

To rotate the key: ship a build signed by the old key that trusts both, add the new key to `AGENT_RELEASE_KEYS`, then ship a build signed by the new key that trusts only it.

**A bad build costs one check-in cycle, not a truck roll.** After swapping, the
new agent must check in successfully within the assignment's deadline (ten
minutes by default). If it does not, the previous build is put back and the
device reports which version failed — so a pilot group tells you something
before a wider one is assigned.

The managed binary lives in `C:\ProgramData\Retune\bin\<version>\`, and the
service points at it. The copy the MSI installed in `Program Files` is a
bootstrap and is never modified, so a repair or an upgrade cannot disturb a
running agent. Only the current and previous versions are kept.

Assigning an older build is a deliberate downgrade and works — it is how a
fleet is recovered from a bad build without touching every machine.

Uploaded builds are stored in `DATA_DIR/agents`, so **back that directory up
with the CA**, and size the volume for it.

A machine with no App Installer reports that plainly and installs nothing.

## Configuration profiles

A script deployment does something. A **profile** states how a machine should
*be*, and the agent keeps it that way: on every check-in it tests each setting,
fixes what has drifted, and reports what it found. Profiles are versioned like
scripts and assigned to groups the same way.

| Kind | What it manages |
|---|---|
| `registry` | one value under `HKLM`, set to a value or removed |
| `service` | a service's startup type and whether it is running |
| `local_group_members` | who is in a local group, `additive` or `exact` |
| `file` | a file's contents, or its absence (up to 1 MB) |
| `firewall_profile` | whether the domain, private or public firewall is on |
| `firewall_rule` | a named inbound or outbound rule |
| `windows_update` | update deferrals, deadlines, pauses, the feature release to stay on, active hours and restart behaviour |
| `bitlocker` | requiring the system drive to be encrypted, and escrowing its recovery key |
| `defender` | Microsoft Defender's real-time monitoring, cloud protection, sample submission, PUA protection and cloud block level |
| `certificate` | a certificate in the machine's trusted root, intermediate or trusted publisher store |
| `wifi` | a Wi-Fi network for every user: open, WPA2-Personal, WPA3-Personal or WPA2-Enterprise (802.1X) |
| `vpn` | a VPN connection for every user: IKEv2 or SSTP |

Each setting is applied as: test, then set only if needed, then **test again**.
That second test is what separates fixing something from merely running
something, and it decides what is reported: `compliant`, `remediated`, `error`
or `conflict`.

**Conflicts.** Every setting has an identity — `service:spooler`,
`registry:HKLM\SOFTWARE\X!Value`. If two assigned profiles set the same
identity to different values, the agent applies **neither** and reports
`conflict` to both, naming the other profile. Picking a winner silently would
make a machine's state depend on assignment order. Two profiles asking for
exactly the same thing is not a conflict.

**Removal.** When a profile stops applying to a device, the agent stops
enforcing it. If the assignment was set to put previous values back, it restores
what was there before the profile first changed each setting — not what Retune
last wrote — and leaves alone anything another profile still wants.

A `file` setting won't read, write or delete through a link: if any folder
on its path, or the file itself, is a junction or symbolic link, the setting
reports an error and nothing is touched. The agent works as SYSTEM, and a
link planted by someone who can write to a folder on the way would otherwise
turn the profile's path into a write anywhere on the machine. Use the real
path (`C:\Users\Public`, not the legacy `C:\Documents and Settings` junction).

A `certificate` setting takes one public certificate as PEM — what
Windows exports as Base-64 `.cer` — and puts it in `root` (trusted root
authorities), `ca` (intermediates) or `trusted_publisher`, all under
`Cert:\LocalMachine`. Its identity is the store and the certificate's
thumbprint, so two profiles trusting the same certificate agree, and
different certificates never conflict. Removing the setting removes the
certificate again, unless it was already there before the profile first
applied. PEM with a private key in it is refused outright: a trust store
takes certificates, and a key pasted into a profile would be sent to every
machine it is assigned to. Client certificates and certificates issued
through SCEP aren't supported.

A `wifi` setting adds a network profile for every user of the machine, from
its name (SSID), security (`open`, `wpa2_personal`, `wpa3_personal`,
`wpa2_enterprise`),
whether to connect automatically and whether the network is hidden. **The
passphrase is write-only**: it is sealed with the server key as soon as it
arrives, the console and API only ever say it is set, and it is opened only
when an assigned device fetches its profile over its mutual-TLS connection.
Leave it empty when editing to keep it; changing it makes a new version. On
the device it reaches `netsh` in a file that is deleted straight after, never
on a command line. A machine without a wireless adapter reports the setting
`not_applicable`, which counts as done.

A **`wpa2_enterprise`** (802.1X) network has no passphrase: each device, or
each user, proves who it is to your RADIUS server. Choose how:

- `"eap_method": "peap"` — PEAP-MSCHAPv2 with the Windows sign-in: the
  machine's domain account, and the user's own once someone signs in;
- `"eap_method": "tls"` — EAP-TLS with a certificate already in the machine's
  or user's store, from your PKI (Active Directory Certificate Services
  autoenrollment, say; Retune doesn't issue client certificates).

and who signs in with `"auth_mode"`: `machine_or_user` (the default),
`machine` or `user`. Two things are required, because without them a device
would give its credentials to any access point claiming the network's name:
`"server_names"`, the names on your RADIUS servers' certificates, and
`"trusted_root_thumbprints"`, the SHA-1 thumbprints of the CA that issued them
(paste them with or without colons and spaces). Devices trust no other server
and never ask the user whether to. Install that root CA with a `certificate`
setting in the same profile. Drift is checked on the method, who signs in, the
server names and the thumbprints.

This has been checked against the WLAN profile schema Windows documents, not
yet on a network with a RADIUS server: try it on a test device first.

A `vpn` setting adds a connection for every user: a name, a server, IKEv2 or
SSTP, and EAP, MS-CHAP v2 or (IKEv2 only) a machine certificate to sign in,
with optional split tunnelling and a DNS suffix. L2TP with a pre-shared key
isn't offered: it's the weakest of Windows' VPN types, and the key would have
to cross a command line.

Removing either setting takes the network or connection away again, or puts
back what was there before the profile first applied.

A `defender` setting enforces only the preferences it names and leaves every
other one as it is. Two profiles that both configure Defender are a conflict
even when they name different preferences, the same as two Windows Update
policies: merging them would apply a configuration nobody wrote. Where
Tamper Protection is on, Defender accepts the change and quietly ignores it;
the agent reads the preferences back, and reports which ones did not take
rather than claiming success. Turn Tamper Protection off for those devices,
or manage those preferences through Intune or Group Policy instead.

`HKCU` registry values are written to the signed-in user's hive, reached by SID
under `HKEY_USERS`. On a machine with nobody signed in the setting reports that
plainly and changes nothing, rather than writing somewhere arbitrary.

Several other things are refused rather than half-supported. An
`exact` group setting never removes the built-in Administrator account, whatever
the profile says. A firewall rule is only removed if Retune created it, so a
profile cannot delete a rule something else on the machine relies on. And
BitLocker never decrypts a drive, never re-encrypts one already encrypted
another way, and refuses to start on a machine with no TPM rather than leaving
it demanding a startup key at every boot.

### BitLocker recovery keys

A `bitlocker` setting can escrow the system drive's recovery password. It is
encrypted before it is stored, with a key in `DATA_DIR/secret.key` that is
created on first use — **back that file up with the CA key, because without it
every escrowed recovery key is unreadable.**

A device's escrowed volumes appear on its page in the console. The key itself is
never part of that listing: showing one is a separate, deliberate action that
requires the admin or helpdesk role and a signed-in session, and is written to
the audit log every time, with who asked and why. A read-only account can see
that a key exists and cannot have it.

### Update rings

A ring is a profile with one `windows_update` setting, assigned to a group:
a pilot group on a short deferral, the broad fleet a week behind it. Beyond
deferrals, the setting can:

- **Set deadlines.** Once an update is offered it installs, restarting if it
  must, within 0–30 days, whatever the user does. A grace period of up to 7
  days spares a machine that was off when the deadline passed from restarting
  the moment it comes back.
- **Pause.** Stops quality or feature updates from a date. Windows lifts a
  pause on its own after 35 days, and the console shows when that will be.
  Remove the pause from the profile to lift it sooner.
- **Hold a feature release.** Keeps machines on, say, Windows 11 24H2. They
  still get that release's monthly updates until you name a newer one.

These are the Windows Update for Business policies under
`HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`, written and put
back like any registry setting. They need an agent from this release: an
older one ignores the fields it doesn't know.

To check patching, use the `os_build_min_per_release` compliance rule with
this month's minimum build for each release in your fleet, and
`updates_within` for "installed something recently". Retune doesn't fetch
Microsoft's release information, so updating the minimums each month is up
to you.

### What each device is missing

Once a day the agent asks Windows Update which updates the device is
missing — the same search Settings runs — and reports them with its
inventory: each update's title, KB number, whether it is a security or
critical update and Microsoft's severity for it, and whether it needs a
restart. The device page lists them, security updates first. The
`max_missing_security_updates` compliance rule turns that into a verdict: a
device missing more security updates than the rule allows is non-compliant,
and one whose search failed, or hasn't reported one in a week, is unknown.

**Install updates…** on a device (admins and helpdesk) installs what Windows
Update is offering now — security and critical updates, or everything,
drivers included — rather than waiting for its own schedule. It restarts only
if you ask it to and an update needs it, five minutes after installing;
otherwise the device reports its updates afresh straight away. Rings still
decide what Windows Update offers: an update a ring is deferring isn't
offered, so isn't installed.

## Compliance

A **compliance policy** states what a healthy device looks like, as a list of
rules, and is assigned to groups the same way profiles and apps are. Nothing
runs on the agent for this: every rule is evaluated server-side from what
inventory, the device row and item statuses already report, right after
inventory arrives and again every 15 minutes so a device that has simply gone
quiet is caught even with no new inventory to react to. "Evaluate now" on a
policy runs it on demand against every device it currently applies to; that
pass runs in the background and reports how it went to the audit log, rather
than holding the request open for a fleet's worth of work.

| Rule | Checks |
|---|---|
| `os_build_min`, `agent_version_min` | a minimum OS build or agent version |
| `os_build_min_per_release` | patched to at least a given build on each Windows release, such as `26100.2605` for 24H2 |
| `bitlocker` | the system drive, or every fixed volume, encrypted |
| `tpm` | a TPM present, optionally at a minimum version |
| `checked_in_within`, `inventory_within` | recent check-in or inventory, in hours |
| `updates_within` | an update installed within some number of days |
| `no_pending_reboot` | no reboot outstanding |
| `max_local_admins` | a ceiling on local administrator accounts |
| `forbidden_software`, `required_software` | a package name absent, or present |
| `profile_applied` | a configuration profile currently `succeeded` on the device |
| `defender_realtime` | Microsoft Defender on, with real-time protection |
| `defender_signatures_within` | Defender's signatures updated within 1–30 days |
| `firewall_enabled` | the firewall on for every profile, or the ones named |
| `max_missing_security_updates` | at most `count` security or critical updates missing, by the device's last Windows Update search |

The Defender and firewall rules read what the agent reports. A device where
another antivirus is primary puts Defender in passive mode, and
`defender_realtime` then reports unknown rather than non-compliant: Defender's
own switch says nothing about whether that machine is protected. Signature
age is measured from when the signatures were last updated to the moment the
rule is evaluated, so a device that stops reporting drifts out of compliance on
its own. The firewall state is the one in effect after Group Policy, not the
locally stored setting a policy may be overriding.

A policy scores each rule as compliant, non-compliant or unknown (a rule with
nothing to evaluate — no inventory yet, say — is unknown rather than a guess
in either direction) and the policy's own state is the worst of its rules. A
device's **overall** compliance is the worst state across every policy
assigned to it, or `not_evaluated` if none applies. Each result is also
mirrored into the same per-device item status apps and profiles use, so a
policy's rollup and a device's page show compliance the same way they show
everything else.

The **Compliance** page lists policies with their compliant/non-compliant
split, an editor for their rules, and per-policy device results filterable by
state. The compliance column on **Devices**, and the compliance section on a
device's own page, both read the same overall and per-policy state.

### Conditional access

Compliance is most useful when something acts on it: only compliant devices
on the corporate Wi-Fi, or into the finance app. Retune answers two ways.

**Asking the server.** Network access control (Aruba ClearPass, Cisco ISE,
and the like) and identity providers can ask whether a device is compliant,
with an API token (read-only is enough):

```
GET /api/admin/v1/compliance/devices?mac=00-15-5D-01-02-03
Authorization: Bearer rtk_…

{"items":[{"device_id":"…","hostname":"PC-042","serial":"…","status":"active",
           "compliance":"compliant","compliant":true,"last_seen_at":"…"}]}
```

Look a device up by one of `mac` (any adapter it last reported, in any
common format), `serial`, `hostname` or `device_id`. `compliant` is the one
answer to act on: true only for an active device compliant with every policy
assigned to it. A device with no policy assigned is `not_evaluated`, and not
compliant — nothing has said it is. Treat an empty answer the same way.

**A statement the device carries.** Every agent keeps a signed statement of
its own compliance at `C:\ProgramData\Retune\compliance.jwt`, refreshed half
an hour before it expires (it lasts an hour). It is an ES256 JWT with
`aud: retune-device-compliance`, `sub` the device ID, and `compliant`, signed
by the Retune CA — whose public key is at
`GET /api/admin/v1/compliance/jwks.json`, no sign-in needed. Software on the
device that gates access, a zero-trust proxy say, can present it; whatever
checks it verifies the signature, the audience and the expiry. It also names
the device's certificate (`cnf.x5t#S256`, RFC 8705), so a relying party that
sees that certificate in TLS can refuse a statement copied from another
machine.

Microsoft Entra ID's own conditional access takes compliance only from
partners it has approved, which needs Microsoft's agreement; these are the
open equivalents.

## Alerts

Everything above, Retune knows silently. An **alert rule** says which of it is
worth interrupting somebody for, and a **notification channel** says where.

| Rule | Fires for |
|---|---|
| A device is non-compliant | each active device failing a compliance policy, or one named policy |
| A device stops checking in | each active device silent for more than *N* hours, or never seen |
| A deployment fails | each failed script, app, profile or agent deployment on an active device |

Rules are evaluated every five minutes, under the same advisory lock the other
sweepers use, so a pair of replicas sends one email rather than two. Each rule
keeps a row for every subject it is currently firing about, which is what makes
the alert about a thing rather than about a moment: **a device that is still
non-compliant on the next pass is not a second email.** It notifies once when a
subject starts firing and once when it stops, and nothing in between — there
are no reminders, and no escalation.

Everything that changed on one pass goes out as one message, twenty subjects
named and the rest counted, so a fleet-wide failure is one thing to read.

**Channels** are email or a webhook.

- Email goes through the relay in `SMTP_HOST` and friends; a channel holds only
  its recipients. Creating an email channel on a deployment with no relay
  configured is refused then and there, rather than accepted and silently never
  delivered.
- A webhook is `POST`ed JSON over https — `{rule, kind, description, at,
  firing: [{subject_key, subject}], resolved: […]}` — with a 10-second timeout.
  Give the channel a shared secret and each request carries
  `X-Retune-Signature: sha256=<hex>` over the exact body. The secret is
  encrypted with the same key that protects escrowed BitLocker recovery keys,
  and can be set or cleared but never read back. A webhook is never sent to a
  loopback or link-local address (the server's own services, or a cloud
  metadata endpoint) and does not follow redirects; addresses on your own
  network are fine. For many receivers the URL is the credential, so
  read-only accounts see only its host.

**Send test** on a channel delivers a fixed message, so a wrong relay or a
typo'd URL is found while you are still looking at the form. Every attempt,
test or otherwise, is on the **Alerts** page for 30 days with whatever the
relay or the receiver said about it.

Deleting a channel a rule still delivers to is refused: quietly deleting the
rules would quietly stop the alerting. Pausing a rule stops its messages but
keeps its state up to date, so resuming it reports what is wrong now rather
than replaying a week.

## Remote actions

A device's page has buttons for one-off commands. Each goes through the
same queue as a script, and its result shows on the **Commands** page. A
command reaches its device within seconds, not at its next check-in: between
check-ins every agent holds a request open on the server, which answers it the
moment a command is queued for that device (through PostgreSQL's
`LISTEN`/`NOTIFY`, so whichever server holds the request hears about it). An
agent talking to an older server, or through a proxy that cuts long requests,
simply falls back to its check-in interval.

| Action | What the device does |
|---|---|
| Run script | runs PowerShell as SYSTEM |
| Refresh inventory | sends a fresh inventory now |
| Restart | restarts, after an optional delay and message |
| Lock | locks the signed-in user's session; with nobody signed in, it succeeds with nothing to lock |
| Collect logs | zips the agent's logs, its last update record, and the System and Application event logs from the last 1–168 hours (up to 50 MiB; anything that won't fit is left out and listed) and uploads it |
| Wipe | resets the device to factory settings through Windows' own MDM remote wipe; a *protected* wipe also removes the recovery partition's data and may leave a device that needs reinstalling |
| Rotate admin password | sets a new random password on the built-in Administrator (or a named local account), escrowed with the server first |
| Install updates | installs security and critical updates, or everything Windows Update offers, restarting only if asked and needed |
| Remote shell | an interactive PowerShell session as SYSTEM (zsh as root on a Mac), recorded; admins only (see below) |
| Rename | gives the device a new computer name (1–15 letters, digits and hyphens), effective at the next restart, or a minute later if you ask it to restart; admins only |

**Remote shell** opens a PowerShell session on the device from the console:
type a line, press Enter, and it runs there as SYSTEM, with its output shown
as it comes. It starts only with a reason, only for an administrator signed
in to the console (not helpdesk, not an API token), and every line typed and
everything written back is kept with the session, in order — the device's page
lists its recent sessions, each with its full transcript, and starting and
ending one is in the audit log. Only the admin who started a session can type
in it, so everything it ran is on one name; another admin who can see the
device can open it to watch, or end it, and an attempt to type is refused and
audited as `remote_session.input_refused`. A session ends when you end it, when the
shell exits, after fifteen minutes with nothing typed, after an hour however
busy, or if the device doesn't join within ten minutes. Agents built to run
only signed code refuse remote shells outright: a live shell would run
unsigned commands. It is a command line, not a remote desktop.

**Collected logs** are kept on the server in `DATA_DIR/command-artifacts`
for 30 days, and downloaded from the command's result on the Commands page.
Event logs can say a good deal about who used a machine, so downloading
needs the admin role and is audited (`command.artifact_downloaded`).

**Wiping** can't be undone, so it asks more of whoever does it:

- one device at a time, by an administrator signed in to the console or the
  server CLI, never an API token;
- the device's hostname typed to confirm, and a reason, both recorded in the
  audit log as `command.wipe_queued`;
- the order lapses after 24 hours, so a lost laptop that comes back online a
  month later doesn't wipe itself on an order nobody remembers.

The device reports the wipe as started once Windows has accepted it, then
resets. It won't report again, and will need enrolling anew.

### Local administrator passwords

**Rotate admin password** gives a machine's built-in Administrator account —
found by its well-known ID, so renaming it doesn't matter — a new random
password of 20–64 characters (24 by default) that avoids look-alike
characters and meets any complexity policy. Name another local account with
`account` on the API or `--account` on the CLI; that takes the admin role,
since whoever rotates a password can reveal it, and helpdesk should not be able
to take over any user or service account on a machine.

The agent **escrows the password with the server before it sets it**: if
the server can't take it, the old password stays and the command fails. A
password set but never stored would be one nobody knows. The new password
is sealed with the server key (`DATA_DIR/secret.key`), bound to its device
and account, and never appears in a command's output or the audit log.

The device page lists each account's passwords with their state:

| State | Meaning |
|---|---|
| In use | the rotation succeeded; this is the current password |
| Being set | escrowed, and the device hasn't reported yet |
| Replaced | a later rotation succeeded |
| Rotation failed | the command failed; the device may still have this password if it failed after setting it |

**Show the password** needs the admin role, a signed-in session (not an API
token) and a reason, and is recorded as `local_admin_password.revealed`
with that reason. Every state can be shown, since a rotation that failed
after setting the password leaves that password in effect. Once you've used
a password, rotate again so it stops working.

This rotates on request, not on a schedule, and doesn't touch domain
accounts or Windows LAPS's own policy; it's for machines that aren't using
Windows LAPS.

## Overview and export

The console's landing page (`/`) is a fleet-wide overview: device counts by
status, the same compliance split, deployments currently failing by kind, and
the top agent versions and OS builds in use — all computed for active devices
only, so a pile of retired machines never skews the picture.

**Devices** and a compliance policy's device list both have an **Export CSV**
link (`GET /devices/export.csv`, `GET
/compliance-policies/{id}/devices/export.csv` on the admin API). Any cell that
would otherwise start with `=`, `+`, `-`, `@`, a tab or a carriage return is
given a leading apostrophe first, so a hostname or failure detail a device
reported can never be read as a spreadsheet formula by whoever opens the file.

### Scheduled reports

Either export can be emailed on a schedule to people who need the numbers but
not a console account — auditors, managers, a security team. On **Scheduled
reports**, choose the device list or one compliance policy's results (all of
them, or only the non-compliant devices, say), up to 20 recipients, and daily
or weekly at an hour in a time zone: `Every Monday at 07:00 Europe/London`.

The report arrives as a CSV attachment, the same file the console's export
would give you, covering the whole fleet. It goes through the mail relay
alerts use, so it needs `SMTP_HOST` and `SMTP_FROM` set; without them a report
is refused when you create it rather than silently never arriving. **Send
now** sends one immediately, to check it gets through. A send that fails is
shown on the report and tried again at its next scheduled time, not every few
minutes until the relay recovers. A CSV over 10 MB isn't attached; the email
says to download it from the console instead. Reports are sent by one server
at a time, so a second replica never sends them twice.

## Cutting a release

Pushing a tag `vMAJOR.MINOR.PATCH` (or `vMAJOR.MINOR.PATCH-rc.1`, published as
a prerelease) runs `.github/workflows/release.yml`. It builds the agent for
Windows, macOS and Linux with the tag's version stamped in, signs every build
with the release key and checks each signature, packages the MSI and the pkg,
builds the server and `retune-sign` binaries, writes `SHA256SUMS`, and
publishes all of it as a GitHub release with the commits since the previous
tag as its notes. It also pushes `ghcr.io/ssan9876/retune-server:<version>`
(and `:latest`, except for a prerelease) for amd64 and arm64.

A pull request that changes the workflow, `deploy/` or `retune-sign` runs the
same builds as a dry run, signed with a key made for that run, and publishes
nothing; its files are kept as the run's `dry-run-release` artifact.

Once, before the first release:

1. Make the release key on a machine you trust, and keep `release.key` off
   the server and out of the repository:

   ```bash
   go run ./cmd/retune-sign keygen --out ~/retune-release
   ```

2. Add its contents as the repository secret `RELEASE_KEY` (**Settings →
   Secrets and variables → Actions**). Without it a tag fails before anything
   is built: agents are never published unsigned.
3. Set `AGENT_RELEASE_KEYS` on every server to the public key from
   `release.pub`, so released builds can be uploaded under **Agent versions**.
4. After the first release, make the `retune-server` package public under the
   repository's **Packages** if servers should pull it without logging in.

Optional:

| Kind | Name | Effect |
|---|---|---|
| variable | `RELEASE_PUBKEYS` | the trust list agents embed, comma-separated; set it while rotating the key (it must include the current key's public key) |
| variable | `OPERATIONS_PUBKEYS` | build released agents that refuse unsigned scripts and wipes (see [Signed scripts and wipes](#signed-scripts-and-wipes)) |
| secrets | `WINDOWS_CERT_PFX` (base64), `WINDOWS_CERT_PASSWORD` | Authenticode-sign the MSI, so a double-click install shows no SmartScreen warning |
| secrets | `MACOS_CERT_P12` (base64, holding both Developer ID certificates), `MACOS_CERT_PASSWORD`, `MACOS_APP_IDENTITY`, `MACOS_INSTALLER_IDENTITY` | code-sign the macOS agent and sign the pkg |
| secrets | `APPLE_ID`, `APPLE_TEAM_ID`, `APPLE_APP_PASSWORD` | notarize and staple the signed pkg |

Without the optional signing secrets the release still goes out, and the run's
summary says which installers are unsigned.

Then, for each release:

```bash
git tag v1.4.0
git push origin v1.4.0
```

## Command-line reference

```
retune-server serve | migrate | healthcheck
retune-server token create [--label L] [--max-uses N] [--expires-in 168h]
retune-server ca fingerprint | ca cert
retune-server device list | show <id> | retire <id> | unenroll <id>
retune-server command queue --device <id> --type <type> [flags] | command show <id>
retune-server bootstrap-admin --email E [--password P] [--role R]
retune-server admin list | create | password | totp | disable | enable

retune-sign keygen | sign | verify

retune-agent enroll --server URL --token T [--pin sha256:...] [--data-dir D]
retune-agent run [--data-dir D] [--once]
retune-agent configure --server URL --token T [--pin sha256:...]   (Windows)
retune-agent install [--data-dir D] | uninstall                    (Windows)
```

## Tests

```bash
go test ./...                 # needs Docker for the database tests
npm --prefix web run test
```

CI runs the Linux suite under `-race`.

The console also has browser tests, which drive Chromium through the built
console against a real server and database. `test/console` starts Postgres
(or uses `DATABASE_URL`), seeds admins and simulated agents through the agent
API, and serves on `https://127.0.0.1:18443`:

```bash
npm --prefix web run build            # the server embeds this build
npx --prefix web playwright install chromium   # once
npm --prefix web run e2e              # needs Docker unless DATABASE_URL is set
```

Locally a server already listening on that port is reused, so a failing run can
be repeated quickly; stop it to start from a fresh database.

## Design and plans

`docs/superpowers/specs` holds the design; `docs/superpowers/plans` holds the
milestone plans, including what is still to come: agent self-update,
compliance rules, the native Windows MDM channel, and macOS and Linux agents.
