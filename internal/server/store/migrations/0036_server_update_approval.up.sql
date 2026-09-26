-- Updating the server itself is held for a second administrator like any
-- other change that reaches the whole fleet.
ALTER TABLE approvals DROP CONSTRAINT approvals_kind_check;
ALTER TABLE approvals ADD CONSTRAINT approvals_kind_check
    CHECK (kind IN ('command', 'assignment', 'version', 'group_member', 'group_rule', 'server_update'));
