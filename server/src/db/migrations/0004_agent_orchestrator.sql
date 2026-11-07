-- Task 10, module 4: Agent Orchestrator v0.
--
-- A workflow run is a fixed, code-defined sequence of agent steps for one
-- trigger (an alert). Each step can only PROPOSE through the action engine;
-- the orchestrator holds no permission of its own.

CREATE TABLE workflow_runs (
  tenant_id     uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  id            uuid        NOT NULL,
  workflow      text        NOT NULL CHECK (workflow ~ '^[a-z_]{1,40}$'),
  trigger_type  text        NOT NULL CHECK (trigger_type IN ('alert')),
  trigger_id    text        NOT NULL CHECK (length(trigger_id) <= 64),
  mode          text        NOT NULL CHECK (mode IN ('shadow', 'simulation')),
  status        text        NOT NULL CHECK (status IN ('running', 'completed', 'failed')),
  steps         jsonb       NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(steps) = 'array' AND jsonb_array_length(steps) <= 20),
  started_by    jsonb       NOT NULL,
  error         text        CHECK (error IS NULL OR length(error) <= 500),
  created_at    timestamptz NOT NULL DEFAULT now(),
  finished_at   timestamptz,
  PRIMARY KEY (tenant_id, id),
  -- One run per workflow, trigger and mode: re-running returns the same run.
  UNIQUE (tenant_id, workflow, trigger_type, trigger_id, mode)
);
CREATE INDEX workflow_runs_tenant_created_idx ON workflow_runs (tenant_id, created_at DESC);
