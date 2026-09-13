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

```bash
./bin/retune-server migrate
./bin/retune-server bootstrap-admin --email you@example.com   # prints a password
./bin/retune-server serve
```

Open `https://<public_url>/` and sign in. With `tls_mode: self-signed` the
server issues its own certificate; agents pin it with the fingerprint from
`retune-server ca fingerprint`.

## Enroll a machine

```powershell
retune-agent.exe enroll --server https://mdm.example.com --token <TOKEN> --pin <FINGERPRINT>
retune-agent.exe run
```

Create the token in the console under Enrollment, which also shows the matching
`msiexec` line once the MSI is available.

## Command-line reference

```
retune-server serve | migrate
retune-server token create [--label L] [--max-uses N] [--expires-in 168h]
retune-server ca fingerprint
retune-server device list | show <id> | retire <id> | unenroll <id>
retune-server command queue --device <id> --type <type> [flags] | command show <id>
retune-server bootstrap-admin --email E [--password P] [--role R]
retune-server admin list | create | password | totp | disable | enable
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
