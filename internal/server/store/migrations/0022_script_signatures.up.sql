-- An operations-key signature over a script version's body and detection
-- script, for agents built to require one.
ALTER TABLE script_versions ADD COLUMN signature jsonb;
