# Running Retune highly available

One server is enough for most fleets (see [sizing](sizing.md)). Run two or more
when the console and the agent API must survive a server failing, or when you
want to patch a machine without an outage. This guide says what that takes,
what Retune already does to make replicas safe, and what still differs between
one server and several.

## The shape

```
            agents, admins
                  │
          load balancer (TCP, or TLS with client certificates)
           ┌──────┴──────┐
     retune-server   retune-server      ← identical, any number
           └──────┬──────┘
        ┌─────────┴──────────┐
   PostgreSQL            shared DATA_DIR
   (with failover)       (NFS, EFS, Azure Files, a CSI RWX volume)
```

Every server runs the same binary with the same configuration. Nothing needs
to be sticky: sessions, commands, assignments, approvals and everything else a
request needs are in the database, and single sign-on keeps its in-flight
state in a sealed cookie rather than in memory.

## What the servers must share

**The database.** One PostgreSQL. For it not to be the single point of failure
itself, use a managed service with automatic failover (RDS Multi-AZ, Azure
Database for PostgreSQL with HA, Cloud SQL HA) or Patroni. Servers reconnect on
their own after a failover; a request in flight at that moment fails, and an
agent tries again after 30 seconds, backing off to at most 30 minutes.

**`DATA_DIR`**, read-write on every server. It holds:

| path | what | written when |
|---|---|---|
| `ca/ca.key`, `ca/ca.crt` | the certificate authority devices trust | first start |
| `secret.key` | the key sealing recovery keys, passwords and secrets | first start |
| `agents/` | uploaded agent builds | an upload |
| `app-packages/` | uploaded MSI and EXE installers | an upload |
| `command-artifacts/` | files commands produced, such as collected logs | a device reports |

A build uploaded through one server is downloaded by devices through another,
so these must be one shared volume, not a copy per server. If you would rather
keep the CA and the secret key out of a shared file system, set
`CA_KEY_SOURCE=env` with `CA_CERT_PEM`, `CA_KEY_PEM` and `SECRET_KEY` on every
server (generate them once with a file-backed server); the three upload
directories still need to be shared.

Starting several servers at once against an empty `DATA_DIR` is safe: they
race to create the CA and the secret key, one wins, and the others wait for
and use what it wrote.

## The load balancer

Either:

- **pass TCP through** (HAProxy `mode tcp`, an AWS NLB, a Kubernetes
  `LoadBalancer` service) to each server's `AGENT_API_LISTEN` port, so each
  server terminates TLS and checks device certificates itself; every server
  then presents a certificate from the shared CA, and agents pin that CA; or
- **terminate TLS at the balancer** and run the servers with
  `tls_mode: behind-proxy`, as the README's *Behind a reverse proxy* section
  describes. The balancer must request client certificates (optionally, since
  enrollment has none yet) and forward them in `client_cert_header`; list its
  addresses in `trusted_proxies`.

Health-check each server with `GET /readyz` (ready when it can reach the
database) and take one out of rotation when it fails. `GET /healthz` only says
the process is alive.

## What is already safe with several servers

| | how |
|---|---|
| database migrations | applied at start under an advisory lock, once |
| background jobs — expiring commands, group and compliance evaluation, alerts, retention, audit streaming, pruning uploads and artifacts, scheduled reports | each run takes an advisory lock; a replica that doesn't get it skips that tick (`retune_sweeper_runs_total{result="skipped"}`) |
| alert emails and webhooks | the alert job runs under a lock, and what each rule is firing about is kept in the database, so a pair of replicas sends one message |
| scheduled reports | claimed with `FOR UPDATE SKIP LOCKED`, so each is sent once |
| two-person approvals | deciding one is a conditional update, so two approvers at once can't both run it |
| creating the CA and the secret key | exclusive file creation; the losers use the winner's |
| rotating the secret key | refuses to run while any server is connected (each holds a lock saying so) |
| sign-in throttling | failed passwords are counted in the database: ten per account in fifteen minutes, however the balancer spreads the guesses |

This is exercised by a test that starts two servers at the same moment
against one database and one empty `DATA_DIR`, signs in through one and uses
the session through the other, enrolls a device through one and checks it in
through the other, and seals a secret on one and opens it on the other.

## What is still per server

- **Metrics.** The fleet gauges come from the database and read the same on
  every server, but the `retune_sweeper_*` series count only the jobs that
  server ran. Scrape every server, and sum.
- **"Evaluate now"** on a compliance policy runs on whichever server took the
  request; if that server stops mid-run, the scheduled evaluation picks it up
  within 15 minutes.

## Upgrading

Migrations run when a server starts, and an older server is not guaranteed to
work against a newer schema. Upgrade by stopping every server, starting one on
the new version (which migrates), then starting the rest — a short outage,
during which agents keep retrying their check-ins with the same backoff. Take
a database backup first, as the README's *Backups* section describes.
