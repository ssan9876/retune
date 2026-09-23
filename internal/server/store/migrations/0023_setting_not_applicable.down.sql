DELETE FROM profile_setting_status WHERE status = 'not_applicable';
ALTER TABLE profile_setting_status DROP CONSTRAINT profile_setting_status_status_check;
ALTER TABLE profile_setting_status ADD CONSTRAINT profile_setting_status_status_check
    CHECK (status IN ('compliant', 'remediated', 'error', 'conflict'));
