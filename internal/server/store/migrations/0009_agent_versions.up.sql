-- An uploaded agent build. The primary key is a uuid because assignments.item_id
-- is uuid, like every other item kind; the version string is what people read
-- and what an agent compares against its own, so it is unique per tenant --
-- uploading the same version twice is a mistake, not a new build.
CREATE TABLE agent_versions (
    id         uuid PRIMARY KEY,
    tenant_id  uuid NOT NULL REFERENCES tenants(id),
    version    text NOT NULL,
    sha256     text NOT NULL,
    size_bytes bigint NOT NULL,
    notes      text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL,
    created_by text NOT NULL
);
CREATE UNIQUE INDEX agent_versions_version ON agent_versions (tenant_id, version);
