-- The retention sweeper deletes history by age. Without these, each of its
-- deletes is a scan of the whole table, repeated every hour.
CREATE INDEX commands_completed ON commands (tenant_id, completed_at) WHERE completed_at IS NOT NULL;
CREATE INDEX script_runs_finished ON script_runs (tenant_id, finished_at);
CREATE INDEX app_installs_finished ON app_installs (tenant_id, finished_at);
