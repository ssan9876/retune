-- Where a build came from: uploaded by an administrator, or imported from a
-- signed release by the release feed.
ALTER TABLE agent_versions ADD COLUMN source text NOT NULL DEFAULT 'upload'
    CHECK (source IN ('upload', 'release_feed'));

-- A release the feed found and verified. manifest is release.json's exact
-- bytes and signature its sidecar, so the verification can be repeated at any
-- time rather than trusted from when it was first done.
CREATE TABLE releases (
    id               uuid PRIMARY KEY,
    tenant_id        uuid NOT NULL REFERENCES tenants(id),
    version          text NOT NULL,
    prerelease       boolean NOT NULL,
    published_at     timestamptz NOT NULL,
    notes            text NOT NULL DEFAULT '',
    manifest         bytea NOT NULL,
    signature        jsonb NOT NULL,
    key_id           text NOT NULL,
    verified_at      timestamptz NOT NULL,
    -- The Windows agent build imported from it, once imported.
    agent_version_id uuid REFERENCES agent_versions(id) ON DELETE SET NULL,
    import_error     text NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX releases_version ON releases (tenant_id, version);

-- When the feed last looked, and what went wrong if it did.
CREATE TABLE release_feed_state (
    tenant_id  uuid PRIMARY KEY REFERENCES tenants(id),
    checked_at timestamptz,
    error      text NOT NULL DEFAULT ''
);

-- Automatic rollout of imported agent builds: off until an administrator
-- turns it on and names a pilot group.
CREATE TABLE agent_rollout_policy (
    tenant_id      uuid PRIMARY KEY REFERENCES tenants(id),
    enabled        boolean NOT NULL DEFAULT false,
    pilot_group_id uuid REFERENCES device_groups(id) ON DELETE SET NULL,
    delay_hours    integer NOT NULL DEFAULT 24 CHECK (delay_hours BETWEEN 1 AND 720),
    updated_at     timestamptz NOT NULL,
    updated_by     text NOT NULL
);

-- One automatic rollout of one build: to the pilot group, then, once the
-- pilot has run for the delay without a rollback, to every device.
CREATE TABLE agent_rollouts (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id),
    agent_version_id      uuid NOT NULL REFERENCES agent_versions(id) ON DELETE CASCADE,
    state                 text NOT NULL CHECK (state IN ('pilot', 'promoting', 'promoted', 'halted', 'superseded')),
    pilot_group_id        uuid REFERENCES device_groups(id) ON DELETE SET NULL,
    delay_hours           integer NOT NULL,
    -- The assignments this rollout made, and the approvals it is waiting on.
    pilot_assignment_id   uuid,
    pilot_approval_id     uuid,
    pilot_started_at      timestamptz,
    exclude_assignment_id uuid,
    fleet_assignment_id   uuid,
    fleet_approval_id     uuid,
    promoted_at           timestamptz,
    -- What it is waiting for, or why it stopped.
    detail                text NOT NULL DEFAULT '',
    created_at            timestamptz NOT NULL,
    updated_at            timestamptz NOT NULL
);
CREATE UNIQUE INDEX agent_rollouts_version ON agent_rollouts (tenant_id, agent_version_id);

-- A halted rollout is something to be told about.
ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_kind_check;
ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_kind_check
    CHECK (kind IN ('device_non_compliant', 'device_stale', 'deployment_failed', 'agent_rollout_halted'));
