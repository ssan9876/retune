CREATE TABLE tenants (
    id   uuid PRIMARY KEY,
    name text NOT NULL
);
INSERT INTO tenants (id, name) VALUES ('00000000-0000-0000-0000-000000000001', 'default');

CREATE TABLE enrollment_tokens (
    id         uuid PRIMARY KEY,
    tenant_id  uuid NOT NULL REFERENCES tenants(id),
    token_hash bytea NOT NULL UNIQUE,
    label      text NOT NULL DEFAULT '',
    expires_at timestamptz,
    max_uses   integer CHECK (max_uses > 0),
    use_count  integer NOT NULL DEFAULT 0,
    revoked_at timestamptz,
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE devices (
    id              uuid PRIMARY KEY,
    tenant_id       uuid NOT NULL REFERENCES tenants(id),
    hostname        text NOT NULL,
    serial          text NOT NULL DEFAULT '',
    smbios_uuid     text NOT NULL DEFAULT '',
    os_version      text NOT NULL DEFAULT '',
    status          text NOT NULL CHECK (status IN ('active', 'retired', 'replaced')),
    cert_serial     text NOT NULL,
    cert_expires_at timestamptz NOT NULL,
    last_seen_at    timestamptz,
    agent_version   text NOT NULL DEFAULT '',
    enrolled_at     timestamptz NOT NULL,
    replaced_by     uuid REFERENCES devices(id)
);
CREATE INDEX devices_active_smbios ON devices (tenant_id, smbios_uuid) WHERE status = 'active';
CREATE INDEX devices_active_serial ON devices (tenant_id, serial) WHERE status = 'active';

CREATE TABLE audit_log (
    id          uuid PRIMARY KEY,
    tenant_id   uuid NOT NULL REFERENCES tenants(id),
    actor       text NOT NULL,
    action      text NOT NULL,
    target_kind text NOT NULL,
    target_id   text NOT NULL,
    details     jsonb NOT NULL DEFAULT '{}',
    at          timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_log_at ON audit_log (tenant_id, at DESC);
