DELETE FROM app_versions WHERE source = 'package';
DROP INDEX IF EXISTS app_versions_file;
ALTER TABLE app_versions
    DROP COLUMN IF EXISTS source,
    DROP COLUMN IF EXISTS installer_type,
    DROP COLUMN IF EXISTS file_name,
    DROP COLUMN IF EXISTS file_sha256,
    DROP COLUMN IF EXISTS file_size,
    DROP COLUMN IF EXISTS uninstall_command,
    DROP COLUMN IF EXISTS success_exit_codes,
    DROP COLUMN IF EXISTS detection,
    DROP COLUMN IF EXISTS uninstall_previous;
