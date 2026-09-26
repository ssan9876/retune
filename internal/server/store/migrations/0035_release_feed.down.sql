DELETE FROM alert_rules WHERE kind = 'agent_rollout_halted';
ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_kind_check;
ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_kind_check
    CHECK (kind IN ('device_non_compliant', 'device_stale', 'deployment_failed'));

DROP TABLE agent_rollouts;
DROP TABLE agent_rollout_policy;
DROP TABLE release_feed_state;
DROP TABLE releases;
ALTER TABLE agent_versions DROP COLUMN source;
