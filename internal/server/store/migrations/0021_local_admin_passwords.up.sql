-- Local administrator passwords set by rotate_local_admin_password, sealed
-- with the server key. A row is pending from escrow until its command
-- reports: then active (and the account's previous active one superseded),
-- or abandoned. The agent escrows before it sets, so the password in effect
-- is always one of these rows.
CREATE TABLE local_admin_passwords (
    id           uuid PRIMARY KEY,
    tenant_id    uuid NOT NULL REFERENCES tenants(id),
    device_id    uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    account      text NOT NULL,
    ciphertext   bytea NOT NULL,
    nonce        bytea NOT NULL,
    state        text NOT NULL CHECK (state IN ('pending', 'active', 'superseded', 'abandoned')),
    -- No foreign key: command retention may delete the command long before
    -- the password stops mattering.
    command_id   uuid NOT NULL UNIQUE,
    created_at   timestamptz NOT NULL,
    activated_at timestamptz
);

CREATE INDEX local_admin_passwords_device ON local_admin_passwords (device_id, created_at DESC);
