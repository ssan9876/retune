-- The helpdesk role: reads, and does the day-to-day device actions - lock,
-- restart, collect logs, rotate the local admin password, reveal a recovery
-- key or password - but changes nothing that runs code or decides policy.
ALTER TABLE admins DROP CONSTRAINT admins_role_check;
ALTER TABLE admins ADD CONSTRAINT admins_role_check CHECK (role IN ('admin', 'helpdesk', 'read_only'));
ALTER TABLE api_tokens DROP CONSTRAINT api_tokens_role_check;
ALTER TABLE api_tokens ADD CONSTRAINT api_tokens_role_check CHECK (role IN ('admin', 'helpdesk', 'read_only'));
