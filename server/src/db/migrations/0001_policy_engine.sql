-- Task 10, module 1: Policy Engine v0.
--
-- A workspace's policy is a sequence of immutable versions; one pointer row says
-- which version is active. Decisions the engine reaches are recorded, also
-- append-only. In v0 every decision is SHADOW: recorded, never enforced.

-- Generic append-only guard for the SOC tables (same rule as audit_log: only a
-- deliberate, documented erasure — tenant deletion — may remove rows).
CREATE OR REPLACE FUNCTION legion_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF coalesce(current_setting('legion.audit_erasure', true), '') = 'on' THEN
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
  END IF;
  RAISE EXCEPTION '% is append-only (% refused)', TG_TABLE_NAME, TG_OP USING ERRCODE = 'insufficient_privilege';
END $$;

CREATE TABLE policy_documents (
  tenant_id   uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  version     int         NOT NULL CHECK (version > 0),
  document    jsonb       NOT NULL,
  hash        text        NOT NULL CHECK (hash ~ '^[0-9a-f]{64}$'),
  created_by  uuid,
  note        text        CHECK (note IS NULL OR length(note) <= 200),
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, version),
  CHECK (octet_length(document::text) <= 65536)
);
CREATE TRIGGER policy_documents_append_only
  BEFORE UPDATE OR DELETE ON policy_documents
  FOR EACH ROW EXECUTE FUNCTION legion_append_only();

CREATE TABLE policy_active (
  tenant_id   uuid        PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
  version     int         NOT NULL,
  updated_by  uuid,
  updated_at  timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, version) REFERENCES policy_documents (tenant_id, version)
);

CREATE TABLE policy_decisions (
  tenant_id        uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  id               uuid        NOT NULL,
  created_at       timestamptz NOT NULL DEFAULT now(),
  enforcement      text        NOT NULL CHECK (enforcement IN ('shadow', 'enforced')),
  call_site        text        NOT NULL CHECK (call_site ~ '^[a-z0-9_.:-]{1,64}$'),
  action_id        text        NOT NULL CHECK (length(action_id) <= 64),
  risk_class       text        CHECK (risk_class IN ('R0', 'R1', 'R2', 'R3', 'R4')),
  actor            jsonb       NOT NULL,
  origin           text        NOT NULL CHECK (origin IN ('human', 'agent', 'llm', 'system')),
  execution_mode   text        NOT NULL CHECK (execution_mode IN ('shadow', 'simulation', 'live')),
  target           text        CHECK (target IS NULL OR length(target) <= 200),
  input_digest     text        CHECK (input_digest IS NULL OR input_digest ~ '^[0-9a-f]{64}$'),
  decision         text        NOT NULL CHECK (decision IN ('ALLOW', 'REQUIRE_APPROVAL', 'RECORD_ONLY', 'DENY')),
  autonomy         text        CHECK (autonomy IN ('OBSERVE', 'ASSIST', 'AUTONOMOUS')),
  matched_rule_ids text[]      NOT NULL DEFAULT '{}',
  reason_codes     text[]      NOT NULL DEFAULT '{}',
  explanation      text        NOT NULL CHECK (length(explanation) <= 2000),
  policy_version   int,
  policy_hash      text,
  catalog_version  text        NOT NULL,
  engine_version   text        NOT NULL,
  legacy_outcome   text        CHECK (legacy_outcome IS NULL OR length(legacy_outcome) <= 64),
  latency_us       int         NOT NULL DEFAULT 0,
  PRIMARY KEY (tenant_id, id)
);
CREATE INDEX policy_decisions_tenant_created_idx ON policy_decisions (tenant_id, created_at DESC);
CREATE TRIGGER policy_decisions_append_only
  BEFORE UPDATE OR DELETE ON policy_decisions
  FOR EACH ROW EXECUTE FUNCTION legion_append_only();
