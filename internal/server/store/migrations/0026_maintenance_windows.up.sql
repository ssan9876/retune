-- Maintenance windows: when a device may be changed, assigned to groups like
-- anything else. The schedule is protocol.Window, sent to the agent as is.
CREATE TABLE maintenance_windows (
    id          uuid PRIMARY KEY,
    tenant_id   uuid NOT NULL REFERENCES tenants(id),
    name        text NOT NULL,
    description text NOT NULL DEFAULT '',
    schedule    jsonb NOT NULL,
    created_at  timestamptz NOT NULL,
    updated_at  timestamptz NOT NULL,
    created_by  text NOT NULL
);
CREATE UNIQUE INDEX maintenance_windows_name ON maintenance_windows (tenant_id, lower(name));
