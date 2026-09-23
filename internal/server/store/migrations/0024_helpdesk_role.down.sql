UPDATE admins SET role = 'read_only' WHERE role = 'helpdesk';
UPDATE api_tokens SET role = 'read_only' WHERE role = 'helpdesk';
ALTER TABLE admins DROP CONSTRAINT admins_role_check;
ALTER TABLE admins ADD CONSTRAINT admins_role_check CHECK (role IN ('admin', 'read_only'));
ALTER TABLE api_tokens DROP CONSTRAINT api_tokens_role_check;
ALTER TABLE api_tokens ADD CONSTRAINT api_tokens_role_check CHECK (role IN ('admin', 'read_only'));
