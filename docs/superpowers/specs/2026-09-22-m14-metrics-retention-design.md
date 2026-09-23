# M14 — Metrics and data retention

Status: approved by the user on 2026-09-22 ("go ahead"), with the §6 decisions as written. Written 2026-09-22 from the overnight draft (`docs/superpowers/drafts/overnight-rulings.md`, "M14"), whose alerting half shipped differently as M13. Builds on merged M1–M13 and the cleanup PR (#1). Decisions that need a yes are collected in §6.

## 1. What and why

Two gaps that only show up once a fleet has been running for a while.

**Nothing is ever deleted.** Every command and its output, every script run, every app install attempt and every audit entry is kept forever. On a 2,000-device fleet with a daily recurring script, `script_runs` alone gains about 730,000 rows a year, and each can carry up to 1 MiB each of stdout and stderr (`protocol.MaxOutputBytes`). The tables get slower to page through, backups get larger, and there is no setting that says how long any of it should be kept.

**Nothing can watch the server from outside.** `/healthz` and `/readyz` say whether it is up. Nothing says whether the sweepers are still running, how many devices have gone quiet, or whether failures are climbing, in a form a monitoring system can graph and alert on. M13's alerts cover the fleet; they do not cover Retune itself — an alert sweeper that has stopped running cannot alert anyone that it stopped.

Out of scope: pruning retired or replaced devices and their inventory (a device row is referenced from almost every table, and whether a retired machine's history should outlive it is a product decision of its own); per-tenant retention settings; HTTP request metrics and latency histograms; OpenTelemetry. No new Go dependencies.

## 2. Retention

### 2.1 What is pruned

| setting | default | removes | age measured from |
|---|---|---|---|
| `AUDIT_RETENTION_DAYS` | 365 | `audit_log` rows | `at` |
| `COMMAND_RETENTION_DAYS` | 90 | finished commands (`succeeded`, `failed`, `timed_out`, `expired`) and their `command_results` | `completed_at` |
| `SCRIPT_RUN_RETENTION_DAYS` | 90 | `script_runs` rows | `finished_at` |
| `APP_INSTALL_RETENTION_DAYS` | 90 | `app_installs` rows | `finished_at` |

`0` disables a table's pruning. Any other value must be 1–3650. `alert_deliveries` keeps the 30-day pruning M13 already gives it and gets no setting.

What is **never** pruned by age, whatever the settings:
- anything still in progress: a queued, delivered or running command;
- current state, as opposed to history: `device_item_status`, `profile_setting_status`, `device_compliance`, inventory and software lists, BitLocker keys, and anything an admin created (scripts, apps, profiles, policies, groups, assignments).

Losing script-run and app-install history does not change what a device is told to do. The agent schedules from its own local state, and the console's rollups read `device_item_status`, not runs. The only readers of `script_runs` and `app_installs` are the two history endpoints (`ListScriptRuns`, `ListAppInstalls`), checked 2026-09-22.

### 2.2 How

- **One job.** A single sweeper job, `retention.prune` with lock id `5274006`, prunes each table in turn. It runs **every hour**, not daily, because the sweeper's tickers start from process start: a daily job on a server restarted more often than daily would never run. When nothing has aged out, a run is four index lookups that find nothing.
- **Batched deletes.** Each table is pruned in batches of 5,000 rows, one statement per batch (`DELETE … WHERE ctid IN (SELECT ctid … LIMIT 5000)`). A first run over years of history therefore never holds one long lock or builds one huge transaction. A run stops after 200 batches per table (a million rows) and picks up on the next tick, so a first run on a huge table cannot hold the advisory lock for an hour.
- **Commands.** A command's result goes first, in the same statement as its batch of commands (a CTE), because `command_results` references `commands` with no cascade.
- **Indexes.** Migration `0013` adds the index each delete needs, since today none of the four `WHERE` clauses has one:
  - `commands (tenant_id, completed_at) WHERE completed_at IS NOT NULL`
  - `script_runs (tenant_id, finished_at)`
  - `app_installs (tenant_id, finished_at)`
  - `audit_log (tenant_id, at DESC)` already exists.
- **Audit.** Each run that removed anything writes one audit entry, `retention.pruned`, with actor `system` and details `{"audit_log": n, "commands": n, "script_runs": n, "app_installs": n}`. History disappearing should itself leave a trace, and one row an hour at most cannot grow without bound. The run is also logged at Info, with the same counts.
- **Replicas.** The advisory lock means only one replica prunes at a time. Every replica must be configured the same; the lock holder's settings win for that tick.

### 2.3 Store

Four methods, each `(ctx, cutoff time.Time, limit int) (int64, error)`, filtering on `DefaultTenantID` like the other bulk writes: `DeleteAuditBefore`, `DeleteFinishedCommandsBefore`, `DeleteScriptRunsBefore`, `DeleteAppInstallsBefore`.

## 3. Metrics

### 3.1 Endpoint

`GET /metrics` goes on the root mux next to the health probes, outside `/api/admin/v1`, because a Prometheus scraper cannot hold a console session. The output is Prometheus text format (`text/plain; version=0.0.4`), written by hand.

- The endpoint is off unless `METRICS_TOKEN` is set, and answers 404 when off. The route is registered either way, because the console's catch-all would otherwise answer `/metrics` with the app shell and a 200. The token must be at least 32 characters, and the server refuses to start with a shorter one.
- Every request must carry `Authorization: Bearer <token>`, compared with `subtle.ConstantTimeCompare`. A missing or wrong token gets a 401 with no body beyond `unauthorized`.
- Behind a proxy, `/metrics` is served like any other path. Operators who don't want it public should keep it off the proxy.

### 3.2 Series

Gauges are recomputed on every scrape, from the aggregate queries the dashboard already uses plus two new ones. The fleet series are the same for every replica, because they come from the shared database. The `sweeper_*` series are counters kept in memory by each process, so they reset on restart and differ per replica, which is what Prometheus expects of counters.

| series | type | source |
|---|---|---|
| `retune_devices{state="active\|stale\|retired"}` | gauge | `DeviceBucketCounts`, with the console's 7-day stale window |
| `retune_compliance_devices{state}` | gauge | `ComplianceCounts` (includes `not_evaluated`) |
| `retune_failed_deployments{kind}` | gauge | `FailedDeploymentCounts` |
| `retune_commands_outstanding{status="queued\|delivered\|running"}` | gauge | new: a count by status of unfinished commands |
| `retune_alerts_firing{kind}` | gauge | new: `alert_state` rows joined to enabled rules, by rule kind |
| `retune_sweeper_runs_total{job,result="ok\|error\|skipped"}` | counter | the runner; `skipped` means another replica held the lock |
| `retune_sweeper_rows_total{job}` | counter | the row counts jobs already return |
| `retune_sweeper_last_success_timestamp_seconds{job}` | gauge | the runner; absent until the job first succeeds |
| `retune_build_info{revision,go_version}` | gauge, always 1 | `runtime/debug.ReadBuildInfo` |

`retune_sweeper_last_success_timestamp_seconds` is the series that answers "is the alert sweeper still running". `time() - retune_sweeper_last_success_timestamp_seconds{job="alerts.evaluate"} > 900` is the one rule the README will suggest.

Label values are bounded: states, statuses, item kinds, rule kinds and job names come from fixed lists. No series is labelled per device, per policy or per rule name.

If a scrape's database query fails, the whole scrape returns 500. A partial exposition would make gauges look like they had dropped to zero.

### 3.3 Runner changes

`sweeper.Runner` gains an optional `Stats` field that records each run's outcome, row count and time, safe to read from the metrics handler concurrently. A nil `Stats` keeps today's behaviour, so tests and callers that don't care stay unchanged.

## 4. Configuration and docs

- New settings, each with an environment variable of the same name in capitals: `metrics_token`, `audit_retention_days`, `command_retention_days`, `script_run_retention_days`, `app_install_retention_days`. They are validated at load and added to the README's settings table.
- Two new README sections:
  - **Metrics:** how to scrape, the series, and the suggested sweeper rule.
  - **Retention:** what is kept, for how long, how to change it, and a warning to raise a horizon *before* upgrading if the defaults would delete history you need.
- `deploy/docker/.env.example` lists the new settings, commented out.
- Roadmap: an M14 row.

## 5. Testing

**Store:**
- Each delete removes exactly the rows older than the cutoff.
- Commands are removed only once finished.
- `limit` is honoured.
- A command's result goes with it.
- Another tenant's rows are untouched.

**Job:**
- `0` disables a table.
- A run removing nothing writes no audit entry; a run removing something writes one, with the counts.
- The per-table batch cap stops a run and the next run continues.

**Metrics (app tests):**
- 404 with no token configured.
- 401 on a missing or wrong token.
- Parsing the output line by line finds every series in §3.2 with the expected values for a small seeded fleet.
- The sweeper counters move after `RunOnce`.
- A database failure gives a 500.

**Config:**
- Every new setting parses and validates, including a token that is too short and out-of-range horizons.

## 6. Decisions to approve

1. **Default horizons:** audit 365 days; commands, script runs and app installs 90 days. On by default, not opt-in, because the reason for this milestone is that nothing is ever deleted. *If wrong:* anyone who needed older history loses it on the first run after upgrading. The README warning and the release notes are the only mitigation.
2. **Audit history is pruned too.** The alternative is to keep the audit log forever and prune only operational history. *If wrong:* an organisation with a multi-year audit requirement has to set `AUDIT_RETENTION_DAYS=0` or a longer horizon.
3. **Hand-written metrics output, with no Prometheus client library.** *If wrong:* adding a series means writing its lines by hand, and there are no histograms without more work.
4. **The metrics endpoint is off unless a token is set, and always needs the token** (no unauthenticated mode for scraping inside a trusted network). *If wrong:* one more secret to configure in Prometheus.
5. **Retired and replaced devices are out of scope.** Their rows, inventory and status stay until a later milestone decides what their history is worth.
