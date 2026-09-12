CREATE TABLE admins (
    id            uuid PRIMARY KEY,
    tenant_id     uuid NOT NULL REFERENCES tenants(id),
    email         text NOT NULL,
    password_hash text NOT NULL,
    totp_secret   text NOT NULL DEFAULT '',
    role          text NOT NULL CHECK (role IN ('admin', 'read_only')),
    created_at    timestamptz NOT NULL,
    last_login_at timestamptz,
    disabled_at   timestamptz
);
CREATE UNIQUE INDEX admins_email ON admins (tenant_id, lower(email));

CREATE TABLE sessions (
    token_hash   bytea PRIMARY KEY,
    tenant_id    uuid NOT NULL REFERENCES tenants(id),
    admin_id     uuid NOT NULL REFERENCES admins(id),
    csrf_token   text NOT NULL,
    created_at   timestamptz NOT NULL,
    expires_at   timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL,
    user_agent   text NOT NULL DEFAULT '',
    ip           text NOT NULL DEFAULT ''
);
CREATE INDEX sessions_admin ON sessions (admin_id);
CREATE INDEX sessions_expiry ON sessions (expires_at);
