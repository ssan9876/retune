-- Uploaded installers (MSI or EXE) beside winget packages. The file itself is
-- stored once per content hash, outside the database.
ALTER TABLE app_versions
    ADD COLUMN source text NOT NULL DEFAULT 'winget' CHECK (source IN ('winget', 'package')),
    ADD COLUMN installer_type text NOT NULL DEFAULT '' CHECK (installer_type IN ('', 'msi', 'exe')),
    ADD COLUMN file_name text NOT NULL DEFAULT '',
    ADD COLUMN file_sha256 text NOT NULL DEFAULT '',
    ADD COLUMN file_size bigint NOT NULL DEFAULT 0,
    ADD COLUMN uninstall_command text NOT NULL DEFAULT '',
    ADD COLUMN success_exit_codes integer[] NOT NULL DEFAULT '{}',
    ADD COLUMN detection jsonb,
    ADD COLUMN uninstall_previous boolean NOT NULL DEFAULT false;

-- Which uploaded files are still in use, for clearing out the rest.
CREATE INDEX app_versions_file ON app_versions (file_sha256) WHERE file_sha256 <> '';
