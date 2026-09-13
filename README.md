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
| Run as | the system account | the signed-in user is stored but **not yet executed** |
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

Running as the signed-in user is accepted and stored, but nothing executes it
yet: those devices report `pending` with that reason rather than appearing to
work. It needs Win32 token work that has not been done.

Every run is kept, so you can see whether a script is flapping rather than only
its latest state. Deleting a script removes its assignments and keeps its runs.

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

Several things are refused rather than half-supported. `HKCU` registry values,
which need the signed-in user's hive, are rejected when the profile is saved. An
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

## Command-line reference

```
retune-server serve | migrate
retune-server token create [--label L] [--max-uses N] [--expires-in 168h]
retune-server ca fingerprint | ca cert
retune-server device list | show <id> | retire <id> | unenroll <id>
retune-server command queue --device <id> --type <type> [flags] | command show <id>
retune-server bootstrap-admin --email E [--password P] [--role R]
retune-server admin list | create | password | totp | disable | enable

retune-agent enroll --server URL --token T [--pin sha256:...] [--data-dir D]
retune-agent run [--data-dir D] [--once]
retune-agent configure --server URL --token T [--pin sha256:...]   (Windows)
retune-agent install | uninstall                                   (Windows)
```

## Tests

```bash
go test ./...                 # needs Docker for the database tests
npm --prefix web run test
```

## Design and plans

`docs/superpowers/specs` holds the design; `docs/superpowers/plans` holds the
milestone plans, including what is still to come: app deployment, compliance
rules, the native Windows MDM channel, and macOS and Linux agents.
