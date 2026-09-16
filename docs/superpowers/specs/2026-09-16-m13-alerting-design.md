# M13 — Alerting

Status: agreed with the user on 2026-09-16 ("do 2 then 1"), after health probes and backup documentation shipped as the smaller piece. Builds on merged M1–M12.

## 1. What and why

Everything Retune knows, it knows silently. A device goes non-compliant, a deployment fails across a group, a laptop stops checking in — and the only way anyone finds out is by opening the console. The dashboard added in the last change makes that a better look, but it is still a look somebody has to take.

Alerting closes the loop: rules over conditions the server already computes, evaluated on a schedule, delivered to email or a webhook, and deduplicated so a fleet-wide problem is one message rather than five hundred.

Out of scope: escalation and on-call rotations, reminders (a subject notifies when it starts firing and when it stops, not every tick in between), acknowledgement and silencing beyond disabling a rule, native Slack or Teams message formats (a webhook carries the JSON; whatever receives it can shape it), SMS, and per-rule schedules. No new Go dependencies: email is `net/smtp` and the webhook is `net/http`.

## 2. Model

- `notification_channels(id uuid PK, tenant_id, name text, kind text CHECK (kind IN ('email','webhook')), config jsonb, secret_ciphertext bytea, secret_nonce bytea, enabled bool, created_at, updated_at, created_by)`, `UNIQUE(tenant_id, name)`.
  - `email` config is `{"to": ["ops@example.com", …]}`, 1–20 addresses. The SMTP server itself is process configuration, not per-channel: one relay per deployment, and a password in a database row that the console can read back is a password nobody should have put there.
  - `webhook` config is `{"url": "https://…"}`, https only. An optional shared secret is sealed with the same `secrets.Key` that protects escrowed BitLocker keys, and is write-only over the API: it can be set and cleared, never read back.
- `alert_rules(id uuid PK, tenant_id, name text, kind text, params jsonb, channel_id uuid REFERENCES notification_channels ON DELETE RESTRICT, enabled bool, created_at, updated_at, created_by)`, `UNIQUE(tenant_id, name)`. `RESTRICT` rather than `CASCADE`: deleting a channel that rules deliver to should say so, not quietly stop the alerts.
- `alert_state(rule_id uuid REFERENCES alert_rules ON DELETE CASCADE, subject_key text, tenant_id, subject text, firing_since timestamptz, notified_at timestamptz)`, PK `(rule_id, subject_key)`. A row exists for exactly as long as that subject is firing; it is deleted when the condition clears. The table is the deduplication — "has this already been reported" is a primary-key lookup, not a scan of what was sent.
- `alert_deliveries(id uuid PK, tenant_id, rule_id, channel_id, at timestamptz, ok bool, detail text, firing int, resolved int)`, indexed on `(tenant_id, at DESC)`. What the console shows when somebody asks why they did not get an email. Pruned after 30 days by the same sweeper.

## 3. Rules

A rule's `params` is a JSON object parsed strictly per kind, in `internal/server/alerts`.

| kind | params | fires for |
|---|---|---|
| `device_non_compliant` | `policy_id` (uuid, optional) | each active device whose overall compliance is `non_compliant` — or, with `policy_id`, non-compliant against that one policy |
| `device_stale` | `hours` 1–8760 | each active device whose last check-in is older than `hours`, or which has never checked in |
| `deployment_failed` | `item_kind` (`script`\|`app`\|`profile`\|`agent`, optional) | each active device with a `failed` item status, of that kind if given |

Each kind is one SQL query returning `(subject_key, subject)` — an opaque stable key and a line a person can read, such as `DESKTOP-4F2 is non-compliant with Baseline security`. The subject key is what deduplicates, so it names the thing that is wrong (`device:<id>`, `device:<id>/item:<kind>:<id>`), never the time it was noticed.

Rules deliberately do not carry their own thresholds for *how many* devices must be affected. A rule that fires on the third device and not the second is a rule nobody can reason about at three in the morning.

## 4. When evaluation runs

A sweeper job, `alerts.evaluate`, lock id `5274005`, every 5 minutes. Per enabled rule:

1. Run the rule's query to get the set of subjects firing now.
2. Compare with `alert_state` for that rule: subjects not present become new rows; rows whose subject is no longer in the set are deleted and counted as resolved.
3. If anything changed, deliver **one** message for the rule — "2 new, 1 resolved", with each subject on its own line, capped at 20 named and a count for the rest — and record the attempt in `alert_deliveries`. On success, `notified_at` is stamped on the new rows.

A delivery failure is recorded and retried on the next tick, because `notified_at` stays null and the rows still count as new. A rule whose channel is disabled evaluates and keeps state but sends nothing, so re-enabling it does not replay a week of history.

The whole job is guarded by the existing advisory lock, so one replica alerts per tick.

## 5. Delivery

- **Email** via `net/smtp` to `SMTP_HOST:SMTP_PORT`, `SMTP_FROM`, optional `SMTP_USERNAME`/`SMTP_PASSWORD`, STARTTLS on by default (`SMTP_STARTTLS=false` for a relay on localhost that does not offer it). Creating an email channel with no SMTP host configured is refused at the API with that reason, rather than accepted and silently never delivered.
- **Webhook**: `POST` of `{"rule":…,"kind":…,"at":…,"firing":[{"subject_key":…,"subject":…}],"resolved":[…]}`, 10-second timeout, https only, and `X-Retune-Signature: sha256=<hex>` over the exact body when the channel has a secret. Any 2xx is success; anything else is a failure with the status in `detail`.

`POST /notification-channels/{id}/test` sends a fixed message through a channel so an administrator can find out that SMTP is wrong while they are looking at the form, not a week later. It needs the write role and is audited.

## 6. Admin API

Reads need any role, mutations need write. All of it is audited as `notification_channel.created|updated|deleted|tested` and `alert_rule.created|updated|deleted`.

- `GET/POST /notification-channels`, `GET/POST/DELETE /notification-channels/{id}`, `POST /notification-channels/{id}/test`. A channel never serialises its secret; it reports `has_secret` instead.
- `GET/POST /alert-rules`, `GET/POST/DELETE /alert-rules/{id}`.
- `GET /alerts` — what is firing now: rule name, kind, subject, firing since, whether it has been notified.
- `GET /alert-deliveries` — the last 50 attempts, newest first.

## 7. Console

One page, **Alerts**, under Tenant administration, in four parts: what is firing now, the rules, the channels, and the recent deliveries. Creating a rule picks a kind, fills in that kind's one parameter, and chooses a channel. Read-only accounts see all of it and can change none of it, as everywhere else.

## 8. Testing

- The rule queries and the fire/resolve diff are tested against a real database, including the case that matters most: a subject that is still firing on the second tick produces no second message.
- Delivery is tested against an `httptest` server for the webhook (including the signature) and a fake SMTP sender for email; the sender is an interface so no test opens a socket to a mail relay.
- Parsing of each kind's params is table-tested without a database.
- The console page is tested like the others, including that a read-only account gets no buttons.
