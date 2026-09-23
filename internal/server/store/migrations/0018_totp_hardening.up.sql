-- The time step of the last TOTP code accepted, so a code can't be used twice.
ALTER TABLE admins ADD COLUMN totp_last_step bigint NOT NULL DEFAULT 0;
