-- TOTP secrets sealed by this version stay sealed: an older server can't read
-- them, so each admin with TOTP must have it turned off and on again
-- (retune-server admin totp --disable, then --enable).
ALTER TABLE admins DROP COLUMN IF EXISTS totp_last_step;
