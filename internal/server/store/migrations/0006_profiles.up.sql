CREATE TABLE profiles (
    id              uuid PRIMARY KEY,
    tenant_id       uuid NOT NULL REFERENCES tenants(id),
    name            text NOT NULL,
    description     text NOT NULL DEFAULT '',
    current_version integer NOT NULL DEFAULT 0,
    created_at      timestamptz NOT NULL,
    updated_at      timestamptz NOT NULL,
    created_by      text NOT NULL
);
CREATE UNIQUE INDEX profiles_name ON profiles (tenant_id, lower(name));

-- Versions are immutable, so a reported status always refers to a known set of
-- settings.
CREATE TABLE profile_versions (
    profile_id uuid NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    version    integer NOT NULL,
    tenant_id  uuid NOT NULL REFERENCES tenants(id),
    settings   jsonb NOT NULL,
    hash       text NOT NULL,
    created_at timestamptz NOT NULL,
    created_by text NOT NULL,
    PRIMARY KEY (profile_id, version)
);

-- One row per setting per device: "the profile failed" is not actionable,
-- "service:Spooler errored: access denied" is.
CREATE TABLE profile_setting_status (
    device_id  uuid NOT NULL REFERENCES devices(id),
    tenant_id  uuid NOT NULL REFERENCES tenants(id),
    profile_id uuid NOT NULL,
    identity   text NOT NULL,
    version    integer NOT NULL,
    status     text NOT NULL CHECK (status IN ('compliant', 'remediated', 'error', 'conflict')),
    detail     text NOT NULL DEFAULT '',
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (device_id, profile_id, identity)
);
CREATE INDEX profile_setting_status_profile ON profile_setting_status (tenant_id, profile_id, status);
