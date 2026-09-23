-- Phased rollouts: an include assignment reaches rollout_percent of its
-- group, widening by rollout_step_percent every rollout_step_hours from when
-- it was made. 100 with no steps is the whole group, as before.
ALTER TABLE assignments
    ADD COLUMN rollout_percent      int NOT NULL DEFAULT 100 CHECK (rollout_percent BETWEEN 1 AND 100),
    ADD COLUMN rollout_step_percent int NOT NULL DEFAULT 0 CHECK (rollout_step_percent BETWEEN 0 AND 100),
    ADD COLUMN rollout_step_hours   int NOT NULL DEFAULT 0 CHECK (rollout_step_hours BETWEEN 0 AND 720);
