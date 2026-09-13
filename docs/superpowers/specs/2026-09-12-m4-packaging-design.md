# M4 — Packaging and Deployment Design

**Parent spec:** `docs/superpowers/specs/2026-09-12-core-platform-design.md` (sections 2, 14, 16)
**Roadmap row:** `docs/superpowers/plans/2026-09-12-roadmap.md` — M4
**Builds on:** merged M1–M3.

## 1. Summary

M4 makes Retune deployable. The server gains a container image, a Compose
stack, a `behind-proxy` TLS mode for running behind a load balancer, and
background sweepers that do the work no request can do. The agent becomes a
Windows service installed by an MSI, logging to the Event Log and a rotating
file instead of a terminal.

Nothing in M4 changes the protocol between agent and server. Every change is
either how a process is started, how it is configured, or work that runs on a
timer.

## 2. Decisions

| Decision | Choice | Why |
|---|---|---|
| `behind-proxy` client certificate | Trusted proxy header carrying the cert, verified by the server against its own CA | Works with nginx, Caddy, Envoy, ALB and Container Apps. TLS passthrough needs no new mode — that is what `provided` already is. |
| Trust model for the header | The proxy delivers bytes; it never supplies a verdict | The server calls `Verify` against its own pool, so a compromised proxy cannot mint devices. |
| Header from an untrusted peer | Reject the request | Silently ignoring a spoofed header hides an attack and produces a confusing `401`. |
| Stale-device flagging | Stays derived on read | It is a `last_seen_at` comparison the list query already makes. Persisting it would add a migration and a column that can go stale, and buy nothing. |
| Sweeper jobs in M4 | Command expiry, expired-session cleanup | Both need a timer today and have none. The framework carries M5's dynamic-group evaluation. |
| Agent enrollment at install | MSI writes config; the service enrolls on first start | A network blip during install does not fail the install. Enrollment converges using the backoff the check-in loop already has. |
| Agent response to `410` | Wipe state, stop, set the service to `Disabled` | Reversible. Re-enrolling needs a token, not a reinstall. A service that uninstalls its own MSI is fiddly and hard to recover when it misfires. |
| MSI signing | Unsigned | No certificate available. Installed by hand or pushed through GPO, neither of which requires one. |
| Verified deployment path | On-prem, self-signed TLS | The path actually being used first. `behind-proxy` is built and unit-tested but not exercised end to end in this milestone. |

## 3. Server configuration

New keys. Each must be added to `fileConfig` **and** to the `set()` map in
`internal/config/file.go` — `dec.KnownFields(true)` makes an omission a parse
error rather than a silently ignored key.

| YAML | Env | Default | Meaning |
|---|---|---|---|
| `tls_mode` | `TLS_MODE` | `self-signed` | now also accepts `behind-proxy` |
| `client_cert_header` | `CLIENT_CERT_HEADER` | `X-Forwarded-Client-Cert` | header carrying the URL-encoded client certificate PEM |
| `trusted_proxies` | `TRUSTED_PROXIES` | empty | comma-separated IPs and CIDRs permitted to send that header |
| `ca_key_source` | `CA_KEY_SOURCE` | `file` | `file` or `env` |
| `sweep_interval_seconds` | `SWEEP_INTERVAL_SECONDS` | `300` | how often sweepers run; minimum 10 |

`config.Server` gains `ClientCertHeader string`, `TrustedProxies []netip.Prefix`,
`CAKeySource string` and `SweepInterval time.Duration`.

### Validation

The TLS switch in `internal/config/server.go` gains a `behind-proxy` case that
**refuses to start** unless `client_cert_header` is non-empty and
`trusted_proxies` parses to at least one network. This is the parent spec's
"the server refuses to start in `behind-proxy` without one of these
configured", made concrete and testable. A bare IP (`10.0.0.5`) is accepted and
treated as a single-address prefix. An unparseable entry is a startup error
naming the offending value.

`ca_key_source=env` requires `CA_KEY_PEM` and `CA_CERT_PEM` to be set and to
parse as a matching key pair; anything else is a startup error.

An existing M1 test asserts `TLS_MODE=behind-proxy` is rejected. It is inverted,
and new cases cover the two refuse-to-start paths.

### Listener

`behind-proxy` serves plain HTTP through `ListenAndServe` with no `TLSConfig`,
because the proxy terminates TLS. `PUBLIC_URL` is still required to be `https`:
it describes the public address, not the socket. `self-signed` and `provided`
are untouched.

## 4. Device authentication

`agentapi.Handler` today reads `r.TLS.VerifiedChains[0][0]` inline. Behind a
proxy there is no `r.TLS`, so the lookup moves behind one field:

```go
// ClientCert returns the device certificate for a request, already verified
// against the internal CA, or (nil, nil) if the request presented none.
ClientCert func(*http.Request) (*x509.Certificate, error)
```

Two implementations live in `internal/server/agentapi/clientcert.go`, chosen by
TLS mode in `app.New`:

- **`TLSClientCert`** — today's behaviour lifted out unchanged: the first
  certificate of the first verified chain, or `nil` when none was presented.
- **`HeaderClientCert(header string, trusted []netip.Prefix, pool *x509.CertPool)`** —
  in order:
  1. Parse `r.RemoteAddr` and check it against `trusted`. If the peer is not
     trusted **and the header is present**, reject with `403 untrusted_proxy`.
     If the peer is not trusted and no header is present, return `(nil, nil)`
     so `/enroll` still works.
  2. Read the header, URL-decode it, and parse the PEM. A malformed value is
     `401 client_cert_invalid`.
  3. `cert.Verify` against the internal CA pool with `ExtKeyUsageClientAuth`.
     A certificate signed by anything else is `401 client_cert_invalid`.

The rejections above are carried by a typed error,
`agentapi.CertError{Status int, Code, Message string}`, so the handler maps a
failure to a response without knowing which implementation produced it. A
`nil` certificate with a `nil` error keeps meaning "no certificate presented",
which is how `/enroll` stays reachable.

Everything downstream is unchanged — the serial match against `cert_serial` and
`prev_cert_serial`, the `unenrolled` → `410`, the status checks — because both
implementations return the same verified `*x509.Certificate`.

Nginx and Envoy emit `X-Forwarded-Client-Cert`; Caddy is configured to. The
header name is configurable because the encoding is not standardised across
proxies, and an operator may need to name whichever header theirs produces.

### Operator support

`retune-server ca cert` prints the CA certificate PEM. A proxy performing the
mTLS handshake needs it to validate client certificates, and there is currently
no way to get it out of the server other than reading the data directory.

`retune-server ca fingerprint` stops creating a CA as a side effect when none
exists; it reports that none exists instead. Creating one silently is
surprising in a container with a fresh empty volume.

## 5. Sweepers

New package `internal/server/sweeper/`.

```go
type Job struct {
    Name     string
    LockID   int64
    Interval time.Duration
    Run      func(context.Context, store.DBTX) (int64, error) // rows affected
}

type Runner struct {
    Store *store.Store
    Jobs  []Job
    Log   *slog.Logger
    Now   func() time.Time
}

func (r *Runner) Start(ctx context.Context)   // one goroutine per job
func (r *Runner) RunOnce(ctx context.Context, j Job) (int64, error)
```

Each tick acquires a dedicated pooled connection, calls
`pg_try_advisory_lock($1)`, and returns immediately if the lock is held —
`try` rather than a blocking acquire, so a second replica skips the tick
instead of queueing behind the first and running the job twice in a row. The
lock is released in a `defer` on the same connection, since advisory locks are
session-scoped and releasing from a different pooled connection is a no-op.

Each tick recovers from panics and logs, matching the agent loop. A failing job
logs at `warn` and is retried on the next tick; it never stops the runner.

Jobs in M4, with fixed lock IDs so they stay stable across restarts and
replicas:

| Job | Lock ID | Work |
|---|---|---|
| `commands.expire` | 5274001 | `ExpireCommands` — marks `queued` commands past their TTL as `expired` |
| `sessions.cleanup` | 5274002 | `DeleteExpiredSessions` — removes admin sessions past `expires_at` |

Both store functions already exist. Neither runs on a timer today:
`ExpireCommands` is called lazily from `Deliver`, so a command queued for a
machine that never checks in stays `queued` forever, and `DeleteExpiredSessions`
is called from no non-test code at all. Those are the two bugs this fixes.

The runner starts in `serve` after `app.New` and stops when the server's
context is cancelled. It is not started by any other CLI command.

## 6. Container image and Compose

`deploy/docker/Dockerfile`, three stages:

1. `node:24-alpine` — `npm ci` and `npm run build`, producing the console into
   `internal/server/console/dist`. This stage is mandatory: the built assets
   are gitignored, and `console.Built()` degrades to a 503 at runtime rather
   than failing the build, so a mis-ordered Dockerfile would ship a server
   whose console is a error page.
2. `golang:1.27` — copies the source and the built console, then
   `CGO_ENABLED=0 go build -o /out/retune-server ./cmd/retune-server`.
3. `gcr.io/distroless/static-debian12:nonroot` — the binary, `USER nonroot`,
   `EXPOSE 8443`, `ENTRYPOINT ["/retune-server"]`, `CMD ["serve"]`.

The data directory (`/var/lib/retune`, holding the CA key) is created in stage
2 owned by uid 65532 and copied in with `--chown`, so that a freshly created
named volume inherits that ownership and the non-root process can write the CA
on first start.

A `.dockerignore` excludes `web/node_modules`, `bin`, `data`, `agent-data` and
`.git`.

`deploy/docker/docker-compose.yml` runs `postgres:17` with a named volume and a
`pg_isready` healthcheck, and the server with `DATABASE_URL`, `PUBLIC_URL`,
`DATA_DIR=/var/lib/retune`, a named volume for the CA, `8443:8443`, and
`depends_on: condition: service_healthy`. No migrate step: `app.New` migrates
at startup under an advisory lock.

An `.env.example` documents `POSTGRES_PASSWORD` and `PUBLIC_URL`. The compose
file reads them from the environment with defaults for a local run.

## 7. Agent as a Windows service

### Refactoring first

The body of `case "run":` in `cmd/retune-agent/main.go` mixes flag parsing with
wiring — identity load, state open, logger, session, signal handling, loop. It
moves to `internal/agent/runner`:

```go
type Options struct {
    DataDir string
    Once    bool
    Log     *slog.Logger
}

// Run performs check-ins until ctx is cancelled. It returns checkin.ErrUnenrolled
// if the server has unenrolled this device.
func Run(ctx context.Context, opts Options) error
```

Both the console path and the service host call it, so the two cannot drift.

### Service host

`cmd/retune-agent/service_windows.go`, behind `//go:build windows`, with a
stub for other platforms so cross-compilation keeps working — the pattern the
agent already uses for facts, keys and inventory.

`svc.IsWindowsService()` decides at startup whether to run under the SCM, so
one binary works both ways and `retune-agent run` in a terminal is unchanged.
Under the SCM, `Execute` reports `StartPending`, then `Running` accepting
`Stop` and `Shutdown`; a stop request cancels the context the runner is using
and the handler reports `StopPending` while the session drains, which is
exactly what `signal.NotifyContext` does today for the console path.

`golang.org/x/sys` is already a direct dependency, so `windows/svc`,
`windows/svc/mgr` and `windows/svc/eventlog` need no new module.

### Subcommands

| Command | Does |
|---|---|
| `retune-agent install` | Registers the `Retune` service, `LocalSystem`, auto-start, with a description and recovery actions (restart after 60s, three attempts), and registers the Event Log source. |
| `retune-agent uninstall` | Stops the service if running, removes it, and deregisters the Event Log source. |
| `retune-agent configure` | Writes `agent.yaml` from `--server`, `--token` and `--pin`, and restricts the data directory's ACL to SYSTEM and Administrators. |

All three are Windows-only and report a clear error elsewhere. All three
require Administrator; they fail with a readable message rather than an
`Access is denied` from the SCM.

### Configuration and first-start enrollment

`C:\ProgramData\Retune\agent.yaml`:

```yaml
server_url: https://mdm.example.com
enroll_token: xxxx
server_cert_fingerprint: sha256:...
```

On start, the service loads its identity. If there is none, it reads
`agent.yaml` and enrolls, retrying with the check-in loop's existing backoff
until it succeeds or the service is stopped. **On success the `enroll_token`
line is removed from the file**, because the token is a credential and is now
spent. If there is no identity and no config, the service logs that it is
unconfigured and idles rather than exiting, so the SCM does not fight it with
restarts.

`server_cert_fingerprint` is optional. Empty means ordinary verification
against the system roots, which is what a deployment behind a proxy with a
publicly trusted certificate wants; the agent client already treats an empty
pin that way.

### Logging

`internal/agent/logging` builds the `slog.Handler`:

- A rotating file at `C:\ProgramData\Retune\logs\agent.log`, rotated at 5 MB,
  keeping five files. Written as a small size-based rotator rather than a new
  dependency.
- The Windows Event Log, source `Retune`, for `warn` and above. Info-level
  chatter every five minutes does not belong in an operator's Event Log.
- Standard error as well, when running interactively.

This is the parent spec's section 14 requirement.

### Unenrollment

When the runner returns `checkin.ErrUnenrolled` under the SCM, the service
wipes identity and state (already implemented in the session), logs to the
Event Log, sets its own start type to `Disabled` through `mgr`, and returns so
the SCM stops it. The MSI stays installed; re-enrolling is `configure` plus a
start.

## 8. MSI

`deploy/msi/Package.wxs`, built with the WiX 5 CLI (`wix build`), which is
already installed on the build machine.

- Per-machine, x64, with a fixed `UpgradeCode` and `MajorUpgrade` so upgrades
  replace in place and downgrades are refused with a readable message.
- Installs `retune-agent.exe` to `Program Files\Retune\`.
- `ServiceInstall` registers `Retune` as auto-start under `LocalSystem`;
  `ServiceControl` starts it on install and stops and removes it on uninstall.
- Public properties `SERVER_URL`, `ENROLL_TOKEN` and `SERVER_CERT_FINGERPRINT`,
  with `ENROLL_TOKEN` listed in `MsiHiddenProperties` so it does not land in
  the installer log.
- A deferred custom action runs `retune-agent configure` with those properties
  before the service starts, so the config file and the data directory ACL are
  written by the same Go code that reads them. Writing them from WiX would
  duplicate that logic in a second language.
- Uninstall removes the data directory, including identity and state. A
  reinstall needs a fresh token regardless, since the old one is spent.

The documented install line, from the parent spec:

```
msiexec /i retune-agent.msi SERVER_URL=https://mdm.example.com ENROLL_TOKEN=xxxx [SERVER_CERT_FINGERPRINT=sha256:...] /qn
```

`deploy/msi/build.ps1` builds the agent for `windows/amd64` and then the MSI,
taking the version as a parameter.

## 9. Build and CI

`Makefile` gains `docker` (builds the image), `msi` (runs `build.ps1`) and
`agent` (cross-compiles the agent binary).

CI gains an MSI build on the existing Windows job — `dotnet tool install
--global wix`, then `build.ps1` — and uploads the result as an artifact, so
every push produces an installable MSI. The Linux job gains a Docker build of
the image. Neither publishes anything; there is no registry and no release
process in this milestone.

## 10. Testing

| Area | How |
|---|---|
| Config | Table tests for each new key, the two `behind-proxy` refuse-to-start paths, `ca_key_source=env` with and without the PEMs, and the inverted M1 case. |
| Header client cert | Table tests: trusted peer with a valid cert; untrusted peer with the header rejected `403`; untrusted peer without it passing through as no cert; malformed PEM; a certificate signed by a different CA rejected. |
| Sweepers | Against a testcontainers Postgres: a queued command past its TTL becomes `expired` without any check-in; an expired session disappears; two runners contending on one lock, where the second tick reports no work rather than repeating it. |
| Agent runner | The existing check-in tests keep passing through the refactor unchanged — that is the point of the refactor. |
| Service host | The SCM layer is kept thin enough to be obvious. `install`/`uninstall` argument handling and the non-Windows stubs are unit-tested; SCM registration itself is verified by running it. |
| Container | Build the image and bring up the Compose stack locally, then enroll a real agent against it and run a script, as M3 was verified. |
| MSI | Built in CI on every push. Installed on a real Windows machine by hand, with the service verified to start, enroll, and survive a reboot. |

## 11. Out of scope

Agent self-update, a registry or release pipeline, KMS-backed CA keys, signed
MSIs, Kubernetes manifests, and end-to-end verification of `behind-proxy`
against a real load balancer. Dynamic-group evaluation is M5's job on the
sweeper framework this milestone builds.
