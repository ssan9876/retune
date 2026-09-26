-- An operations-key signature over an app version's definition and over a
-- profile version's settings, for agents built to require one.
ALTER TABLE app_versions ADD COLUMN signature jsonb;
ALTER TABLE profile_versions ADD COLUMN signature jsonb;
