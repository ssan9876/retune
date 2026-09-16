# Retune

Endpoint management for Windows machines, self-hosted on-prem or in the cloud.
One server binary serves the agent API, the admin API and the console; a small
Go agent runs on each machine.

## What works today

- **Enrollment.** A one-time token enrolls a machine; the server issues it a
  client certificate and the agent checks in over mutual TLS.
- **Inventory.** Hardware, operating system, disks, network adapters, installed
  software and local accounts, refreshed daily or on demand.
- **Commands.** Run a PowerShell script, restart a machine, or refresh its
  inventory, with results (exit code and output) reported back.
- **Lifecycle.** Certificates renew before expiry; retiring a device stops its
  check-ins; unenrolling makes the agent delete its own identity and state.
- **Console and admin API.** Sign-in with password and optional authenticator
  codes, roles (admin and read-only), enrollment tokens, and an audit log.
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
- **Compliance.** Policies assigned to groups that say what a healthy device
  looks like — encryption, patch level, check-in recency, forbidden or
  required software and more — evaluated server-side from what is already
  reported, with no agent involvement.
- **Overview dashboard and CSV export.** A fleet-wide landing page, and CSV
  export of the device list and of one policy's results.
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
| `session_ttl_hours` | `12` | console session lifetime (1–168) |
| `sweep_interval_seconds` | `300` | how often expired commands and sessions are cleared (minimum 10) |
| `agent_release_keys` | — | comma-separated public keys that sign agent builds; uploads are refused until set |

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
    }
}
```

Agents reaching a proxy with a publicly trusted certificate need no pin;
`--pin` and `SERVER_CERT_FINGERPRINT` are for self-signed servers.

## Enroll a machine

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
Build the MSI with `pwsh deploy/msi/build.ps1` (or `make msi`), which needs the
WiX 5 CLI: `dotnet tool install --global wix`.

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

Apps live under **Apps**. An app is a winget package — a package ID, and
optionally an exact version. Every change to what gets installed creates a new
immutable version; renaming or re-describing an app does not.

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
| `windows_update` | update deferrals, active hours and restart behaviour |
| `bitlocker` | requiring the system drive to be encrypted, and escrowing its recovery key |

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
requires the admin role and is written to the audit log every time, with who
asked and why. A read-only account can see that a key exists and cannot have it.

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
| `bitlocker` | the system drive, or every fixed volume, encrypted |
| `tpm` | a TPM present, optionally at a minimum version |
| `checked_in_within`, `inventory_within` | recent check-in or inventory, in hours |
| `updates_within` | an update installed within some number of days |
| `no_pending_reboot` | no reboot outstanding |
| `max_local_admins` | a ceiling on local administrator accounts |
| `forbidden_software`, `required_software` | a package name absent, or present |
| `profile_applied` | a configuration profile currently `succeeded` on the device |

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

## Command-line reference

```
retune-server serve | migrate
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

## Design and plans

`docs/superpowers/specs` holds the design; `docs/superpowers/plans` holds the
milestone plans, including what is still to come: agent self-update,
compliance rules, the native Windows MDM channel, and macOS and Linux agents.
