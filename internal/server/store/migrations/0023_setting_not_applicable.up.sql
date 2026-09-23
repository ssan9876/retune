-- A setting a machine can't have and doesn't need, such as Wi-Fi on a
-- machine with no wireless adapter.
ALTER TABLE profile_setting_status DROP CONSTRAINT profile_setting_status_status_check;
ALTER TABLE profile_setting_status ADD CONSTRAINT profile_setting_status_status_check
    CHECK (status IN ('compliant', 'remediated', 'error', 'conflict', 'not_applicable'));
