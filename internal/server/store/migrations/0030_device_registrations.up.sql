-- Zero-touch provisioning: devices registered by serial number before they
-- arrive, with the groups they join and the name they get when they enroll.
CREATE TABLE device_registrations (
    id          uuid PRIMARY KEY,
    tenant_id   uuid NOT NULL REFERENCES tenants(id),
    serial      text NOT NULL,
    device_name text NOT NULL DEFAULT '',
    group_ids   uuid[] NOT NULL DEFAULT '{}',
    notes       text NOT NULL DEFAULT '',
    device_id   uuid REFERENCES devices(id) ON DELETE SET NULL,
    enrolled_at timestamptz,
    created_at  timestamptz NOT NULL,
    created_by  text NOT NULL
);
CREATE UNIQUE INDEX device_registrations_serial ON device_registrations (tenant_id, upper(serial));

-- A token that enrolls only registered devices: one that leaks enrolls no
-- stranger's machine.
ALTER TABLE enrollment_tokens ADD COLUMN registered_only boolean NOT NULL DEFAULT false;
