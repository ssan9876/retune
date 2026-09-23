-- API tokens let scripts and integrations call the admin API without a
-- browser session. Only a hash of each token is kept. A token belongs to the
-- admin who made it: disabling that admin stops every token they made.
CREATE TABLE api_tokens (
    id            uuid PRIMARY KEY,
    tenant_id     uuid NOT NULL REFERENCES tenants(id),
    name          text NOT NULL,
    token_hash    bytea NOT NULL UNIQUE,
    role          text NOT NULL CHECK (role IN ('admin', 'read_only')),
    created_by_id uuid NOT NULL REFERENCES admins(id),
    created_by    text NOT NULL,
    created_at    timestamptz NOT NULL,
    expires_at    timestamptz NOT NULL,
    last_used_at  timestamptz,
    revoked_at    timestamptz
);

-- A name identifies a live token; a revoked one gives its name back.
CREATE UNIQUE INDEX api_tokens_name ON api_tokens (tenant_id, lower(name)) WHERE revoked_at IS NULL;
