-- How far each audit destination has been sent. The cursor is the position
-- (at, id) of the last entry delivered; delivery is at least once, from there.
CREATE TABLE audit_stream_cursors (
    tenant_id  uuid NOT NULL REFERENCES tenants(id),
    sink       text NOT NULL,
    last_at    timestamptz NOT NULL,
    last_id    uuid NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, sink)
);

-- The stream reads forward in (at, id) order.
CREATE INDEX audit_log_stream ON audit_log (tenant_id, at, id);
