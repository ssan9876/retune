ALTER TABLE devices DROP CONSTRAINT devices_status_check;
ALTER TABLE devices ADD CONSTRAINT devices_status_check
    CHECK (status IN ('active', 'retired', 'replaced', 'unenrolled'));
ALTER TABLE devices
    ADD COLUMN prev_cert_serial text NOT NULL DEFAULT '',
    ADD COLUMN os_build         text NOT NULL DEFAULT '',
    ADD COLUMN manufacturer     text NOT NULL DEFAULT '',
    ADD COLUMN model            text NOT NULL DEFAULT '';

CREATE TABLE device_inventory (
    device_id     uuid PRIMARY KEY REFERENCES devices(id),
    tenant_id     uuid NOT NULL REFERENCES tenants(id),
    collected_at  timestamptz NOT NULL,
    received_at   timestamptz NOT NULL,
    hash          text NOT NULL,
    software_hash text NOT NULL,
    data          jsonb NOT NULL,
    ram_gb        double precision NOT NULL DEFAULT 0,
    disk_free_gb  double precision NOT NULL DEFAULT 0
);

CREATE TABLE device_software (
    device_id    uuid NOT NULL REFERENCES devices(id),
    tenant_id    uuid NOT NULL REFERENCES tenants(id),
    name         text NOT NULL,
    version      text NOT NULL DEFAULT '',
    publisher    text NOT NULL DEFAULT '',
    install_date text NOT NULL DEFAULT '',
    scope        text NOT NULL DEFAULT 'machine'
);
CREATE INDEX device_software_device ON device_software (device_id);
CREATE INDEX device_software_name ON device_software (tenant_id, lower(name));

CREATE TABLE commands (
    id           uuid PRIMARY KEY,
    tenant_id    uuid NOT NULL REFERENCES tenants(id),
    device_id    uuid NOT NULL REFERENCES devices(id),
    type         text NOT NULL,
    payload      jsonb NOT NULL DEFAULT '{}',
    status       text NOT NULL CHECK (status IN ('queued', 'delivered', 'running', 'succeeded', 'failed', 'timed_out', 'expired')),
    created_by   text NOT NULL,
    created_at   timestamptz NOT NULL,
    delivered_at timestamptz,
    started_at   timestamptz,
    completed_at timestamptz,
    expires_at   timestamptz NOT NULL
);
CREATE INDEX commands_pending ON commands (device_id, created_at)
    WHERE status IN ('queued', 'delivered', 'running');

CREATE TABLE command_results (
    command_id       uuid PRIMARY KEY REFERENCES commands(id),
    tenant_id        uuid NOT NULL REFERENCES tenants(id),
    exit_code        integer NOT NULL,
    stdout           text NOT NULL DEFAULT '',
    stderr           text NOT NULL DEFAULT '',
    stdout_truncated boolean NOT NULL DEFAULT false,
    stderr_truncated boolean NOT NULL DEFAULT false,
    error            text NOT NULL DEFAULT '',
    started_at       timestamptz NOT NULL,
    finished_at      timestamptz NOT NULL
);
