-- Accounts that sign in through an identity provider. They are keyed by the
-- provider's issuer and subject, never by email: not every provider verifies
-- addresses, and matching on one would hand a local account to whoever
-- controls that address at the provider.
ALTER TABLE admins
    ADD COLUMN auth_source text NOT NULL DEFAULT 'local' CHECK (auth_source IN ('local', 'oidc')),
    ADD COLUMN oidc_issuer text,
    ADD COLUMN oidc_subject text,
    ADD CONSTRAINT admins_oidc_identity CHECK (
        (auth_source = 'oidc' AND oidc_issuer IS NOT NULL AND oidc_subject IS NOT NULL)
        OR (auth_source = 'local' AND oidc_issuer IS NULL AND oidc_subject IS NULL));

CREATE UNIQUE INDEX admins_oidc_subject ON admins (tenant_id, oidc_issuer, oidc_subject)
    WHERE oidc_subject IS NOT NULL;
