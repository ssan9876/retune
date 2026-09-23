-- Two-person approval: a request held until a second administrator approves
-- or rejects it. The request is stored as it was made and replayed, as the
-- person who made it, when approved.
CREATE TABLE approvals (
    id              uuid PRIMARY KEY,
    tenant_id       uuid NOT NULL REFERENCES tenants(id),
    kind            text NOT NULL CHECK (kind IN ('command', 'assignment')),
    request         jsonb NOT NULL,
    summary         text NOT NULL,
    requested_by    text NOT NULL,
    -- The person behind the request: the admin, or the admin who made the
    -- API token. Nobody approves what they asked for themselves.
    requester_id    uuid NOT NULL,
    created_at      timestamptz NOT NULL,
    expires_at      timestamptz NOT NULL,
    status          text NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'approved', 'rejected', 'expired', 'failed')),
    decided_by      text NOT NULL DEFAULT '',
    decided_at      timestamptz,
    decision_reason text NOT NULL DEFAULT '',
    result          jsonb
);
CREATE INDEX approvals_pending ON approvals (tenant_id, created_at) WHERE status = 'pending';
CREATE INDEX approvals_created ON approvals (tenant_id, created_at DESC);
