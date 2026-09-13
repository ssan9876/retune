CREATE TABLE apps (
    id              uuid PRIMARY KEY,
    tenant_id       uuid NOT NULL REFERENCES tenants(id),
    name            text NOT NULL,
    description     text NOT NULL DEFAULT '',
    current_version integer NOT NULL DEFAULT 0,
    created_at      timestamptz NOT NULL,
    updated_at      timestamptz NOT NULL,
    created_by      text NOT NULL
);
CREATE UNIQUE INDEX apps_name ON apps (tenant_id, lower(name));

-- Versions are immutable: an install is only meaningful if you know what was
-- asked for. Scope is constrained rather than free text because the agent runs
-- as LocalSystem, where a per-user install would land in the system account's
-- profile rather than any real person's.
CREATE TABLE app_versions (
    app_id         uuid NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    version        integer NOT NULL,
    tenant_id      uuid NOT NULL REFERENCES tenants(id),
    package_id     text NOT NULL,
    pinned_version text NOT NULL DEFAULT '',
    scope          text NOT NULL DEFAULT 'machine' CHECK (scope IN ('machine')),
    install_args   text NOT NULL DEFAULT '',
    hash           text NOT NULL,
    created_at     timestamptz NOT NULL,
    created_by     text NOT NULL,
    PRIMARY KEY (app_id, version)
);

-- app_id has no foreign key on purpose: installs outlive the app, because what
-- happened on a machine stays true after the app is deleted.
CREATE TABLE app_installs (
    id                uuid PRIMARY KEY,
    tenant_id         uuid NOT NULL REFERENCES tenants(id),
    app_id            uuid NOT NULL,
    version           integer NOT NULL,
    device_id         uuid NOT NULL REFERENCES devices(id),
    intent            text NOT NULL CHECK (intent IN ('install', 'uninstall')),
    status            text NOT NULL CHECK (status IN ('succeeded', 'failed')),
    -- What winget reports afterwards, so the console can say which version a
    -- device actually has rather than only which one was asked for.
    installed_version text NOT NULL DEFAULT '',
    exit_code         integer NOT NULL,
    stdout            text NOT NULL DEFAULT '',
    stderr            text NOT NULL DEFAULT '',
    stdout_truncated  boolean NOT NULL DEFAULT false,
    stderr_truncated  boolean NOT NULL DEFAULT false,
    error             text NOT NULL DEFAULT '',
    detail            text NOT NULL DEFAULT '',
    started_at        timestamptz NOT NULL,
    finished_at       timestamptz NOT NULL
);
CREATE INDEX app_installs_recent ON app_installs (app_id, device_id, started_at DESC);
