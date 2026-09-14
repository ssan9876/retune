-- Every build is signed by an offline release key from M11 on. The table
-- shipped in M10 with nothing deployed, so the columns are required outright.
ALTER TABLE agent_versions
    ADD COLUMN key_id    text NOT NULL,
    ADD COLUMN signature text NOT NULL;
