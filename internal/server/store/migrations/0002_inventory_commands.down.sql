DROP TABLE command_results;
DROP TABLE commands;
DROP TABLE device_software;
DROP TABLE device_inventory;
ALTER TABLE devices
    DROP COLUMN model,
    DROP COLUMN manufacturer,
    DROP COLUMN os_build,
    DROP COLUMN prev_cert_serial;
ALTER TABLE devices DROP CONSTRAINT devices_status_check;
ALTER TABLE devices ADD CONSTRAINT devices_status_check
    CHECK (status IN ('active', 'retired', 'replaced'));
