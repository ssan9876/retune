-- A policy has no versions: it is edited in place and every assigned device
-- is simply re-evaluated against whatever the rules say now.
CREATE TABLE compliance_policies (
    id          uuid PRIMARY KEY,
    tenant_id   uuid NOT NULL REFERENCES tenants(id),
    name        text NOT NULL,
    description text NOT NULL DEFAULT '',
    rules       jsonb NOT NULL,
    created_at  timestamptz NOT NULL,
    updated_at  timestamptz NOT NULL,
    created_by  text NOT NULL,
    UNIQUE (tenant_id, name)
);

-- One row per (device, policy) the policy currently applies to. A row is
-- deleted, not marked stale, once the policy no longer applies to that
-- device, so a listing never has to filter out assignments that ended.
CREATE TABLE device_compliance (
    device_id    uuid NOT NULL REFERENCES devices(id),
    policy_id    uuid NOT NULL REFERENCES compliance_policies(id) ON DELETE CASCADE,
    tenant_id    uuid NOT NULL REFERENCES tenants(id),
    state        text NOT NULL CHECK (state IN ('compliant', 'non_compliant', 'unknown')),
    failures     jsonb NOT NULL DEFAULT '[]',
    evaluated_at timestamptz NOT NULL,
    PRIMARY KEY (device_id, policy_id)
);
CREATE INDEX device_compliance_policy_state ON device_compliance (tenant_id, policy_id, state);
