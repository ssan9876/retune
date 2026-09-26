-- One agent version can now be built for several platforms. The version is
-- still what an administrator assigns; each device is handed the build that
-- matches its own operating system and processor.
CREATE TABLE agent_version_builds (
    agent_version_id uuid NOT NULL REFERENCES agent_versions(id) ON DELETE CASCADE,
    tenant_id        uuid NOT NULL REFERENCES tenants(id),
    -- GOOS-GOARCH, or darwin-universal for a Mac build of both processors.
    platform         text NOT NULL,
    sha256           text NOT NULL,
    size_bytes       bigint NOT NULL,
    key_id           text NOT NULL,
    signature        text NOT NULL,
    created_at       timestamptz NOT NULL,
    created_by       text NOT NULL,
    PRIMARY KEY (agent_version_id, platform)
);

-- Every build uploaded before this was for Windows: nothing else could update
-- itself. Their bytes stay where they are; the store finds them there.
INSERT INTO agent_version_builds (agent_version_id, tenant_id, platform, sha256, size_bytes, key_id, signature, created_at, created_by)
SELECT id, tenant_id, 'windows-amd64', sha256, size_bytes, key_id, signature, created_at, created_by
FROM agent_versions;

-- What a device runs on, as its agent reports it on every check-in. Empty for
-- an agent too old to say.
ALTER TABLE devices ADD COLUMN platform text NOT NULL DEFAULT '';
