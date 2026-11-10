-- Task 10, module 3: Action Engine v0.
--
-- Every action anyone (person, agent, Legion) wants done becomes one row here,
-- passes the policy engine, waits for approval when required, and is then
-- SIMULATED: v0 computes what would happen and changes nothing. The database
-- itself refuses live execution and refuses to let a high-risk action move
-- past approval without an approval attached.

CREATE TABLE action_requests (
  tenant_id          uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  id                 uuid        NOT NULL,
  idempotency_key    text        NOT NULL CHECK (idempotency_key ~ '^[A-Za-z0-9_.:-]{8,100}$'),
  action_id          text        NOT NULL CHECK (length(action_id) <= 64),
  risk_class         text        NOT NULL CHECK (risk_class IN ('R0', 'R1', 'R2', 'R3', 'R4')),
  input              jsonb       NOT NULL CHECK (octet_length(input::text) <= 8192),
  action_digest      text        NOT NULL CHECK (action_digest ~ '^[0-9a-f]{64}$'),
  target             text        CHECK (target IS NULL OR length(target) <= 200),
  reason             text        CHECK (reason IS NULL OR length(reason) <= 500),
  actor              jsonb       NOT NULL,
  origin             text        NOT NULL CHECK (origin IN ('human', 'agent', 'llm', 'system')),
  -- v0: live is not a possible value. Turning it on needs a new migration.
  execution_mode     text        NOT NULL CHECK (execution_mode IN ('shadow', 'simulation')),
  status             text        NOT NULL CHECK (status IN ('denied', 'recorded', 'awaiting_approval', 'rejected', 'expired',
                                                           'cancelled', 'queued', 'running', 'simulated', 'failed')),
  policy_decision    text        NOT NULL CHECK (policy_decision IN ('ALLOW', 'REQUIRE_APPROVAL', 'RECORD_ONLY', 'DENY')),
  policy_decision_id uuid        NOT NULL,
  approval_id        uuid,
  result             jsonb       CHECK (result IS NULL OR octet_length(result::text) <= 16384),
  error              text        CHECK (error IS NULL OR length(error) <= 500),
  attempts           int         NOT NULL DEFAULT 0,
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, idempotency_key),
  FOREIGN KEY (tenant_id, approval_id) REFERENCES approval_requests (tenant_id, id),
  -- Nothing the policy did not allow, or a person did not approve, ever runs.
  CHECK (status NOT IN ('queued', 'running', 'simulated', 'failed') OR policy_decision = 'ALLOW' OR approval_id IS NOT NULL),
  -- Critical actions run only with an approval, whoever asked.
  CHECK (risk_class <> 'R4' OR status NOT IN ('queued', 'running', 'simulated', 'failed') OR approval_id IS NOT NULL)
);
CREATE INDEX action_requests_tenant_created_idx ON action_requests (tenant_id, created_at DESC);
CREATE INDEX action_requests_tenant_status_idx ON action_requests (tenant_id, status);

-- Every state change, append-only: who moved the action from what to what.
CREATE TABLE action_events (
  tenant_id   uuid        NOT NULL,
  action_id   uuid        NOT NULL,
  seq         bigserial   NOT NULL,
  from_status text,
  to_status   text        NOT NULL,
  actor       jsonb       NOT NULL,
  note        text        CHECK (note IS NULL OR length(note) <= 500),
  at          timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, action_id, seq),
  FOREIGN KEY (tenant_id, action_id) REFERENCES action_requests (tenant_id, id) ON DELETE CASCADE
);
CREATE TRIGGER action_events_append_only
  BEFORE UPDATE OR DELETE ON action_events
  FOR EACH ROW EXECUTE FUNCTION legion_append_only();

-- The workspace's emergency stop for the SOC core. While paused, nothing new is
-- accepted and nothing queued runs.
CREATE TABLE soc_controls (
  tenant_id      uuid        PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
  actions_paused boolean     NOT NULL DEFAULT false,
  reason         text        CHECK (reason IS NULL OR length(reason) <= 500),
  changed_by     uuid,
  changed_at     timestamptz NOT NULL DEFAULT now()
);
