CREATE TABLE device_groups (
    id           uuid PRIMARY KEY,
    tenant_id    uuid NOT NULL REFERENCES tenants(id),
    name         text NOT NULL,
    description  text NOT NULL DEFAULT '',
    kind         text NOT NULL CHECK (kind IN ('static', 'dynamic', 'builtin')),
    rule         text NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL,
    updated_at   timestamptz NOT NULL,
    evaluated_at timestamptz
);
CREATE UNIQUE INDEX device_groups_name ON device_groups (tenant_id, lower(name));

-- A group is static or dynamic, never both, so a membership row needs no
-- column saying where it came from: the group's kind already says.
CREATE TABLE group_members (
    group_id  uuid NOT NULL REFERENCES device_groups(id) ON DELETE CASCADE,
    device_id uuid NOT NULL REFERENCES devices(id),
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    added_at  timestamptz NOT NULL,
    PRIMARY KEY (group_id, device_id)
);
CREATE INDEX group_members_device ON group_members (device_id);

-- item_id has no foreign key: the tables it points at arrive in M6 and M7.
CREATE TABLE assignments (
    id         uuid PRIMARY KEY,
    tenant_id  uuid NOT NULL REFERENCES tenants(id),
    item_kind  text NOT NULL,
    item_id    uuid NOT NULL,
    group_id   uuid NOT NULL REFERENCES device_groups(id) ON DELETE CASCADE,
    mode       text NOT NULL CHECK (mode IN ('include', 'exclude')),
    created_at timestamptz NOT NULL,
    created_by text NOT NULL
);
CREATE UNIQUE INDEX assignments_unique ON assignments (item_kind, item_id, group_id, mode);
CREATE INDEX assignments_group ON assignments (group_id);

CREATE TABLE device_item_status (
    device_id  uuid NOT NULL REFERENCES devices(id),
    tenant_id  uuid NOT NULL REFERENCES tenants(id),
    item_kind  text NOT NULL,
    item_id    uuid NOT NULL,
    status     text NOT NULL CHECK (status IN ('pending', 'succeeded', 'failed', 'conflict', 'not_applicable')),
    detail     text NOT NULL DEFAULT '',
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (device_id, item_kind, item_id)
);
CREATE INDEX device_item_status_item ON device_item_status (tenant_id, item_kind, item_id, status);

-- The built-in group exists so an item can be assigned to the whole fleet
-- without building a group first. Its membership is derived, like a dynamic
-- group's, but it has no rule.
INSERT INTO device_groups (id, tenant_id, name, description, kind, created_at, updated_at)
VALUES ('00000000-0000-0000-0000-000000000002',
        '00000000-0000-0000-0000-000000000001',
        'All devices', 'Every active device.', 'builtin', now(), now());
