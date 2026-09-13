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
authority: **losing it orphans every enrolled device**, so back it up.

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
