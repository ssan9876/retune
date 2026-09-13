-- A recovery key unlocks a laptop, so it is never stored in plain text: the
-- ciphertext and nonce are AES-GCM under a server key kept beside the CA.
CREATE TABLE bitlocker_keys (
    id         uuid PRIMARY KEY,
    tenant_id  uuid NOT NULL REFERENCES tenants(id),
    device_id  uuid NOT NULL REFERENCES devices(id),
    volume_id  text NOT NULL,
    method     text NOT NULL DEFAULT '',
    ciphertext bytea NOT NULL,
    nonce      bytea NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);
CREATE UNIQUE INDEX bitlocker_keys_volume ON bitlocker_keys (device_id, volume_id);
