-- Where an alert goes. The SMTP relay itself is process configuration, not a
-- row here: one relay per deployment, and a password the console could read
-- back is a password nobody should have stored.
CREATE TABLE notification_channels (
    id                uuid PRIMARY KEY,
    tenant_id         uuid NOT NULL REFERENCES tenants(id),
    name              text NOT NULL,
    kind              text NOT NULL CHECK (kind IN ('email', 'webhook')),
    config            jsonb NOT NULL,
    -- A webhook's shared secret, sealed with the same key that protects
    -- escrowed BitLocker recovery keys. Write-only over the API.
    secret_ciphertext bytea,
    secret_nonce      bytea,
    enabled           boolean NOT NULL DEFAULT true,
    created_at        timestamptz NOT NULL,
    updated_at        timestamptz NOT NULL,
    created_by        text NOT NULL,
    UNIQUE (tenant_id, name)
);

-- What is worth telling somebody about. ON DELETE RESTRICT on the channel:
-- deleting one that rules deliver to should say so, not quietly stop them.
CREATE TABLE alert_rules (
    id         uuid PRIMARY KEY,
    tenant_id  uuid NOT NULL REFERENCES tenants(id),
    name       text NOT NULL,
    kind       text NOT NULL CHECK (kind IN ('device_non_compliant', 'device_stale', 'deployment_failed')),
    params     jsonb NOT NULL DEFAULT '{}',
    channel_id uuid NOT NULL REFERENCES notification_channels(id) ON DELETE RESTRICT,
    enabled    boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    created_by text NOT NULL,
    UNIQUE (tenant_id, name)
);

-- One row for exactly as long as a subject is firing, deleted when it clears.
-- This table is the deduplication: "have we already said this" is a primary
-- key lookup rather than a search through what was sent.
CREATE TABLE alert_state (
    rule_id      uuid NOT NULL REFERENCES alert_rules(id) ON DELETE CASCADE,
    subject_key  text NOT NULL,
    tenant_id    uuid NOT NULL REFERENCES tenants(id),
    subject      text NOT NULL,
    firing_since timestamptz NOT NULL,
    -- Null until a delivery for this subject has succeeded, so a failed send
    -- is simply retried on the next tick.
    notified_at  timestamptz,
    PRIMARY KEY (rule_id, subject_key)
);

-- What the console shows when somebody asks why they never got the email.
CREATE TABLE alert_deliveries (
    id         uuid PRIMARY KEY,
    tenant_id  uuid NOT NULL REFERENCES tenants(id),
    rule_id    uuid NOT NULL REFERENCES alert_rules(id) ON DELETE CASCADE,
    channel_id uuid NOT NULL REFERENCES notification_channels(id) ON DELETE CASCADE,
    at         timestamptz NOT NULL,
    ok         boolean NOT NULL,
    detail     text NOT NULL DEFAULT '',
    firing     integer NOT NULL DEFAULT 0,
    resolved   integer NOT NULL DEFAULT 0
);
CREATE INDEX alert_deliveries_recent ON alert_deliveries (tenant_id, at DESC);
