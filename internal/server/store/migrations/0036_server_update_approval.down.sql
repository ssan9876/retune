DELETE FROM approvals WHERE kind = 'server_update';
ALTER TABLE approvals DROP CONSTRAINT approvals_kind_check;
ALTER TABLE approvals ADD CONSTRAINT approvals_kind_check
    CHECK (kind IN ('command', 'assignment', 'version', 'group_member', 'group_rule'));
