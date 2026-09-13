CREATE TABLE scripts (
    id              uuid PRIMARY KEY,
    tenant_id       uuid NOT NULL REFERENCES tenants(id),
    name            text NOT NULL,
    description     text NOT NULL DEFAULT '',
    current_version integer NOT NULL DEFAULT 0,
    created_at      timestamptz NOT NULL,
    updated_at      timestamptz NOT NULL,
    created_by      text NOT NULL
);
CREATE UNIQUE INDEX scripts_name ON scripts (tenant_id, lower(name));

-- Versions are immutable: a run is only meaningful if you know what ran.
CREATE TABLE script_versions (
    script_id      uuid NOT NULL REFERENCES scripts(id) ON DELETE CASCADE,
    version        integer NOT NULL,
    tenant_id      uuid NOT NULL REFERENCES tenants(id),
    body           text NOT NULL,
    detection_body text NOT NULL DEFAULT '',
    hash           text NOT NULL,
    created_at     timestamptz NOT NULL,
    created_by     text NOT NULL,
    PRIMARY KEY (script_id, version)
);

-- script_id has no foreign key on purpose: runs outlive the script, because
-- what happened on a machine stays true after the script is deleted.
CREATE TABLE script_runs (
    id               uuid PRIMARY KEY,
    tenant_id        uuid NOT NULL REFERENCES tenants(id),
    script_id        uuid NOT NULL,
    version          integer NOT NULL,
    device_id        uuid NOT NULL REFERENCES devices(id),
    status           text NOT NULL CHECK (status IN ('succeeded', 'failed', 'timed_out')),
    -- Which phase produced the outcome, so a failure reads at a glance.
    phase            text NOT NULL CHECK (phase IN ('script', 'detection', 'remediation')),
    remediated       boolean NOT NULL DEFAULT false,
    exit_code        integer NOT NULL,
    stdout           text NOT NULL DEFAULT '',
    stderr           text NOT NULL DEFAULT '',
    stdout_truncated boolean NOT NULL DEFAULT false,
    stderr_truncated boolean NOT NULL DEFAULT false,
    error            text NOT NULL DEFAULT '',
    started_at       timestamptz NOT NULL,
    finished_at      timestamptz NOT NULL
);
CREATE INDEX script_runs_recent ON script_runs (script_id, device_id, started_at DESC);

-- M5 left assignments without options because the items they configure did
-- not exist yet. Scripts are the first.
ALTER TABLE assignments ADD COLUMN options jsonb NOT NULL DEFAULT '{}';

-- Which version the latest status refers to, so the console can say
-- "succeeded on version 3" rather than just "succeeded".
ALTER TABLE device_item_status ADD COLUMN version integer NOT NULL DEFAULT 0;
