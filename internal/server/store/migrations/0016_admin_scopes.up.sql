-- An admin with rows here sees and manages only the devices in those groups;
-- one with none is unscoped and sees the whole fleet, as before.
CREATE TABLE admin_scopes (
    admin_id  uuid NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    group_id  uuid NOT NULL REFERENCES device_groups(id) ON DELETE CASCADE,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    PRIMARY KEY (admin_id, group_id)
);

-- A scoped admin whose last group is deleted must not become unscoped - which
-- is what an admin with no rows means - so the admin keeps a marker saying
-- they are scoped at all.
ALTER TABLE admins ADD COLUMN scoped boolean NOT NULL DEFAULT false;
