DROP INDEX IF EXISTS admins_oidc_subject;
ALTER TABLE admins
    DROP CONSTRAINT IF EXISTS admins_oidc_identity,
    DROP COLUMN IF EXISTS oidc_subject,
    DROP COLUMN IF EXISTS oidc_issuer,
    DROP COLUMN IF EXISTS auth_source;
