-- Failed sign-ins, counted here rather than in each server's memory so the
-- limit holds however many servers share the database.
CREATE TABLE login_failures (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    key       text NOT NULL,
    at        timestamptz NOT NULL
);
CREATE INDEX login_failures_key ON login_failures (tenant_id, key, at);
CREATE INDEX login_failures_at ON login_failures (at);
