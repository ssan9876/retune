-- Scheduled reports: a CSV export emailed on a schedule, to people who need
-- the numbers but not a console account.
CREATE TABLE scheduled_reports (
    id           uuid PRIMARY KEY,
    tenant_id    uuid NOT NULL REFERENCES tenants(id),
    name         text NOT NULL,
    kind         text NOT NULL CHECK (kind IN ('devices', 'compliance')),
    policy_id    uuid REFERENCES compliance_policies(id) ON DELETE CASCADE,
    state        text NOT NULL DEFAULT '',
    recipients   text[] NOT NULL,
    frequency    text NOT NULL CHECK (frequency IN ('daily', 'weekly')),
    weekday      int NOT NULL DEFAULT 1 CHECK (weekday BETWEEN 0 AND 6),
    hour         int NOT NULL CHECK (hour BETWEEN 0 AND 23),
    timezone     text NOT NULL DEFAULT 'UTC',
    enabled      boolean NOT NULL DEFAULT true,
    next_run_at  timestamptz NOT NULL,
    last_sent_at timestamptz,
    last_error   text NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL,
    updated_at   timestamptz NOT NULL,
    created_by   text NOT NULL,
    CHECK ((kind = 'compliance') = (policy_id IS NOT NULL))
);
CREATE UNIQUE INDEX scheduled_reports_name ON scheduled_reports (tenant_id, lower(name));
CREATE INDEX scheduled_reports_due ON scheduled_reports (next_run_at) WHERE enabled;
