-- Two-person approval covers the ways around it: a new version of something
-- already sent to many devices, a device added to a group that already has
-- code assigned, and a dynamic group's rule changed under its assignments.
ALTER TABLE approvals DROP CONSTRAINT approvals_kind_check;
ALTER TABLE approvals ADD CONSTRAINT approvals_kind_check
    CHECK (kind IN ('command', 'assignment', 'version', 'group_member', 'group_rule'));

-- Ad-hoc PowerShell is counted per administrator over the last hour, so a
-- request split into small ones still waits.
CREATE INDEX commands_powershell_by ON commands (tenant_id, created_by, created_at)
    WHERE type = 'run_powershell';
