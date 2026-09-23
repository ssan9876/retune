-- A file a command produced, such as collect_logs' archive. The bytes live in
-- DATA_DIR/command-artifacts/<command_id>.zip; this row says they are whole.
CREATE TABLE command_artifacts (
    command_id uuid PRIMARY KEY REFERENCES commands(id) ON DELETE CASCADE,
    tenant_id  uuid NOT NULL REFERENCES tenants(id),
    size_bytes bigint NOT NULL,
    sha256     text NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE INDEX command_artifacts_created ON command_artifacts (created_at);
