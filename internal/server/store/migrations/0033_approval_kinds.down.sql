DROP INDEX commands_powershell_by;
DELETE FROM approvals WHERE kind NOT IN ('command', 'assignment');
ALTER TABLE approvals DROP CONSTRAINT approvals_kind_check;
ALTER TABLE approvals ADD CONSTRAINT approvals_kind_check CHECK (kind IN ('command', 'assignment'));
