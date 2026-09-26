import type { Pool } from "pg";

/*
 * Idempotent: safe to run on every start, like Legion's own migrate().
 *
 * tenant_id and owner_user_id are TEXT without foreign keys because the host
 * schema (tenants.id / users.id types) was not available when this module was
 * written. Ownership and tenancy are validated through HostAdapter on every
 * write and every request. When wiring into server/, add:
 *   ALTER TABLE machine_identities ADD FOREIGN KEY (tenant_id) REFERENCES tenants(id);
 *   ALTER TABLE machine_identities ADD FOREIGN KEY (owner_user_id) REFERENCES users(id);
 * (with a ::text cast / matching column type).
 */
export const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS machine_identities (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        text NOT NULL,
  kind             text NOT NULL CHECK (kind IN ('ai_agent', 'service_account')),
  name             text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
  description      text NOT NULL DEFAULT '' CHECK (length(description) <= 1000),
  owner_user_id    text NOT NULL,
  status           text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'revoked')),
  status_reason    text CHECK (length(status_reason) <= 500),
  permissions      text[] NOT NULL DEFAULT '{}',
  risk_level       text NOT NULL CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),
  created_at       timestamptz NOT NULL DEFAULT now(),
  created_by       text NOT NULL,
  updated_at       timestamptz NOT NULL DEFAULT now(),
  expires_at       timestamptz,
  revoked_at       timestamptz,
  last_activity_at timestamptz,
  last_activity_ip text,
  CHECK ((status = 'revoked') = (revoked_at IS NOT NULL))
);
-- A name identifies one live identity per tenant and kind; revoked names can be reused.
CREATE UNIQUE INDEX IF NOT EXISTS machine_identities_live_name
  ON machine_identities (tenant_id, kind, lower(name)) WHERE status <> 'revoked';
CREATE INDEX IF NOT EXISTS machine_identities_tenant ON machine_identities (tenant_id, kind, status);

CREATE TABLE IF NOT EXISTS machine_credentials (
  id           uuid PRIMARY KEY,
  identity_id  uuid NOT NULL REFERENCES machine_identities(id),
  tenant_id    text NOT NULL,
  secret_hash  bytea NOT NULL CHECK (length(secret_hash) = 32),
  created_at   timestamptz NOT NULL DEFAULT now(),
  created_by   text NOT NULL,
  expires_at   timestamptz,
  revoked_at   timestamptz,
  last_used_at timestamptz
);
CREATE INDEX IF NOT EXISTS machine_credentials_identity ON machine_credentials (identity_id);

CREATE TABLE IF NOT EXISTS machine_tokens (
  token_hash    bytea PRIMARY KEY CHECK (length(token_hash) = 32),
  identity_id   uuid NOT NULL REFERENCES machine_identities(id),
  credential_id uuid NOT NULL REFERENCES machine_credentials(id),
  tenant_id     text NOT NULL,
  token_id      uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE,
  issued_at     timestamptz NOT NULL DEFAULT now(),
  expires_at    timestamptz NOT NULL,
  revoked_at    timestamptz
);
CREATE INDEX IF NOT EXISTS machine_tokens_identity ON machine_tokens (identity_id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS machine_tokens_expiry ON machine_tokens (expires_at);

-- Who did what, for every principal type. Append-only and hash-chained per
-- tenant: each row's hash covers its content and the previous row's hash, so
-- editing or deleting history is detectable (verifyAuditChain).
CREATE TABLE IF NOT EXISTS principal_audit_log (
  seq            bigserial PRIMARY KEY,
  chain_key      text NOT NULL,
  occurred_at    timestamptz NOT NULL,
  tenant_id      text,
  principal_type text NOT NULL CHECK (principal_type IN ('human', 'ai_agent', 'service_account', 'external_system')),
  principal_id   text NOT NULL,
  principal_name text NOT NULL,
  on_behalf_of   text,
  credential_id  text,
  action         text NOT NULL,
  resource_type  text,
  resource_id    text,
  outcome        text NOT NULL CHECK (outcome IN ('attempt', 'success', 'failure', 'denied')),
  reason         text,
  request_id     text,
  ip             text,
  user_agent     text,
  details        jsonb NOT NULL DEFAULT '{}',
  prev_hash      text NOT NULL,
  hash           text NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS principal_audit_chain ON principal_audit_log (chain_key, seq);
CREATE INDEX IF NOT EXISTS principal_audit_tenant_time ON principal_audit_log (tenant_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS principal_audit_principal
  ON principal_audit_log (tenant_id, principal_type, principal_id, seq DESC);
CREATE INDEX IF NOT EXISTS principal_audit_resource
  ON principal_audit_log (tenant_id, resource_type, resource_id, seq DESC);

CREATE OR REPLACE FUNCTION principal_audit_log_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'principal_audit_log is append-only (% refused)', TG_OP;
END $$;
DROP TRIGGER IF EXISTS principal_audit_log_no_update ON principal_audit_log;
CREATE TRIGGER principal_audit_log_no_update
  BEFORE UPDATE OR DELETE ON principal_audit_log
  FOR EACH ROW EXECUTE FUNCTION principal_audit_log_append_only();
DROP TRIGGER IF EXISTS principal_audit_log_no_truncate ON principal_audit_log;
CREATE TRIGGER principal_audit_log_no_truncate
  BEFORE TRUNCATE ON principal_audit_log
  FOR EACH STATEMENT EXECUTE FUNCTION principal_audit_log_append_only();

-- ---- Agent firewall ---------------------------------------------------------

-- Every version of every tenant's policy is kept; the highest version applies.
CREATE TABLE IF NOT EXISTS firewall_policies (
  tenant_id  text NOT NULL,
  version    integer NOT NULL CHECK (version > 0),
  policy     jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  created_by text NOT NULL,
  PRIMARY KEY (tenant_id, version)
);

-- One row per firewall decision, written BEFORE the action runs. Append-only,
-- hash-chained per tenant like principal_audit_log.
CREATE TABLE IF NOT EXISTS firewall_decisions (
  seq             bigserial PRIMARY KEY,
  chain_key       text NOT NULL,
  decision_id     uuid NOT NULL UNIQUE,
  occurred_at     timestamptz NOT NULL,
  tenant_id       text NOT NULL,
  principal_type  text NOT NULL,
  principal_id    text NOT NULL,
  principal_name  text NOT NULL,
  owner_user_id   text NOT NULL,
  credential_id   text,
  token_id        text,
  delegated_user  text,
  delegation_id   text,
  agent_chain     text[] NOT NULL DEFAULT '{}',
  via_message_id  text,
  surface         text NOT NULL,
  action          text NOT NULL,
  permission      text,
  resource_type   text,
  resource_id     text,
  sensitivity     text NOT NULL,
  destination     text,
  decision        text NOT NULL CHECK (decision IN ('ALLOW', 'WARN', 'BLOCK')),
  would_block     boolean NOT NULL,
  mode            text NOT NULL,
  risk_score      integer NOT NULL,
  risk_factors    jsonb NOT NULL,
  rule_hits       jsonb NOT NULL,
  advisor         jsonb NOT NULL,
  policy_version  integer NOT NULL,
  input_digest    text NOT NULL,
  input_preview   jsonb NOT NULL,
  request_id      text,
  ip              text,
  prev_hash       text NOT NULL,
  hash            text NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS firewall_decisions_chain ON firewall_decisions (chain_key, seq);
CREATE INDEX IF NOT EXISTS firewall_decisions_tenant ON firewall_decisions (tenant_id, seq DESC);
CREATE INDEX IF NOT EXISTS firewall_decisions_principal ON firewall_decisions (tenant_id, principal_id, seq DESC);
CREATE INDEX IF NOT EXISTS firewall_decisions_blocked ON firewall_decisions (tenant_id, seq DESC) WHERE decision <> 'ALLOW';
DROP TRIGGER IF EXISTS firewall_decisions_no_update ON firewall_decisions;
CREATE TRIGGER firewall_decisions_no_update
  BEFORE UPDATE OR DELETE ON firewall_decisions
  FOR EACH ROW EXECUTE FUNCTION principal_audit_log_append_only();
DROP TRIGGER IF EXISTS firewall_decisions_no_truncate ON firewall_decisions;
CREATE TRIGGER firewall_decisions_no_truncate
  BEFORE TRUNCATE ON firewall_decisions
  FOR EACH STATEMENT EXECUTE FUNCTION principal_audit_log_append_only();

-- A person lets an agent act on their behalf, for a subset of their own
-- permissions, for a limited time. Granted by that person, never by the agent.
CREATE TABLE IF NOT EXISTS agent_delegations (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   text NOT NULL,
  identity_id uuid NOT NULL REFERENCES machine_identities(id),
  user_id     text NOT NULL,
  permissions text[] NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz NOT NULL,
  revoked_at  timestamptz,
  revoked_by  text
);
CREATE INDEX IF NOT EXISTS agent_delegations_lookup
  ON agent_delegations (tenant_id, identity_id, user_id) WHERE revoked_at IS NULL;

-- Agent-to-agent messages relayed by Legion. The recipient's later actions
-- that cite a message are limited to what it asked for, and carry its chain.
CREATE TABLE IF NOT EXISTS agent_messages (
  id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id            text NOT NULL,
  from_identity        uuid NOT NULL REFERENCES machine_identities(id),
  to_identity          uuid NOT NULL REFERENCES machine_identities(id),
  requested_permission text NOT NULL,
  payload              jsonb NOT NULL,
  chain                text[] NOT NULL DEFAULT '{}',
  decision_id          uuid NOT NULL,
  created_at           timestamptz NOT NULL DEFAULT now(),
  expires_at           timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS agent_messages_inbox ON agent_messages (tenant_id, to_identity, created_at DESC);

-- ---- Prompt-injection guard -------------------------------------------------

-- Suspicious or malicious external content, attributed to the principal it
-- reached. Evidence: append-only and hash-chained per tenant. Raw content is
-- NOT stored — only a digest, its length and a short redacted preview.
CREATE TABLE IF NOT EXISTS content_ingestion_log (
  seq             bigserial PRIMARY KEY,
  chain_key       text NOT NULL,
  event_id        uuid NOT NULL UNIQUE,
  occurred_at     timestamptz NOT NULL,
  tenant_id       text NOT NULL,
  principal_type  text NOT NULL,
  principal_id    text NOT NULL,
  principal_name  text NOT NULL,
  source          text NOT NULL,
  source_id       text,
  field_hint      text,
  verdict         text NOT NULL CHECK (verdict IN ('clean', 'suspicious', 'malicious')),
  risk_score      integer NOT NULL,
  findings        jsonb NOT NULL,
  content_digest  text NOT NULL,
  content_length  integer NOT NULL,
  content_preview text NOT NULL,
  request_id      text,
  prev_hash       text NOT NULL,
  hash            text NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS content_ingestion_chain ON content_ingestion_log (chain_key, seq);
CREATE INDEX IF NOT EXISTS content_ingestion_principal ON content_ingestion_log (tenant_id, principal_id, seq DESC);
CREATE INDEX IF NOT EXISTS content_ingestion_verdict ON content_ingestion_log (tenant_id, verdict, seq DESC);
DROP TRIGGER IF EXISTS content_ingestion_no_update ON content_ingestion_log;
CREATE TRIGGER content_ingestion_no_update
  BEFORE UPDATE OR DELETE ON content_ingestion_log
  FOR EACH ROW EXECUTE FUNCTION principal_audit_log_append_only();
DROP TRIGGER IF EXISTS content_ingestion_no_truncate ON content_ingestion_log;
CREATE TRIGGER content_ingestion_no_truncate
  BEFORE TRUNCATE ON content_ingestion_log
  FOR EACH STATEMENT EXECUTE FUNCTION principal_audit_log_append_only();

-- A person reviewed a principal's flagged content up to this point. A
-- cursor, not evidence: the flagged events themselves are never changed.
CREATE TABLE IF NOT EXISTS content_risk_acknowledgements (
  tenant_id                text NOT NULL,
  principal_id             text NOT NULL,
  acknowledged_through_seq bigint NOT NULL,
  acknowledged_by          text NOT NULL,
  acknowledged_at          timestamptz NOT NULL DEFAULT now(),
  reason                   text NOT NULL,
  PRIMARY KEY (tenant_id, principal_id)
);

-- ---- Tool gateway -----------------------------------------------------------

-- Every blocked or high-risk tool call, and what happened when it ran.
-- Append-only and hash-chained per tenant.
CREATE TABLE IF NOT EXISTS tool_call_audit (
  seq                  bigserial PRIMARY KEY,
  chain_key            text NOT NULL,
  event_id             uuid NOT NULL UNIQUE,
  phase                text NOT NULL CHECK (phase IN ('decision', 'outcome', 'ticket_verified', 'ticket_rejected')),
  occurred_at          timestamptz NOT NULL,
  tenant_id            text NOT NULL,
  principal_type       text NOT NULL,
  principal_id         text NOT NULL,
  principal_name       text NOT NULL,
  owner_user_id        text,
  delegated_user       text,
  tool_kind            text NOT NULL,
  operation            text NOT NULL,
  target               text NOT NULL,
  destination          text NOT NULL,
  permission           text,
  decision             text NOT NULL CHECK (decision IN ('ALLOW', 'WARN', 'BLOCK')),
  risk_score           integer NOT NULL,
  high_risk            boolean NOT NULL,
  rule_ids             text[] NOT NULL,
  rule_hits            jsonb NOT NULL,
  firewall_decision_id uuid NOT NULL,
  call_digest          text NOT NULL,
  call_preview         jsonb NOT NULL,
  outcome              text,
  outcome_detail       text,
  output_verdict       text,
  request_id           text,
  prev_hash            text NOT NULL,
  hash                 text NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS tool_call_audit_chain ON tool_call_audit (chain_key, seq);
CREATE INDEX IF NOT EXISTS tool_call_audit_tenant ON tool_call_audit (tenant_id, seq DESC);
CREATE INDEX IF NOT EXISTS tool_call_audit_principal ON tool_call_audit (tenant_id, principal_id, seq DESC);
CREATE INDEX IF NOT EXISTS tool_call_audit_decision ON tool_call_audit (firewall_decision_id);
DROP TRIGGER IF EXISTS tool_call_audit_no_update ON tool_call_audit;
CREATE TRIGGER tool_call_audit_no_update
  BEFORE UPDATE OR DELETE ON tool_call_audit
  FOR EACH ROW EXECUTE FUNCTION principal_audit_log_append_only();
DROP TRIGGER IF EXISTS tool_call_audit_no_truncate ON tool_call_audit;
CREATE TRIGGER tool_call_audit_no_truncate
  BEFORE TRUNCATE ON tool_call_audit
  FOR EACH STATEMENT EXECUTE FUNCTION principal_audit_log_append_only();

-- Proof, for a tool server, that Legion approved exactly this call. Single
-- use, short-lived, bound to the digest of the call's arguments.
CREATE TABLE IF NOT EXISTS tool_call_tickets (
  ticket_hash  bytea PRIMARY KEY CHECK (length(ticket_hash) = 32),
  tenant_id    text NOT NULL,
  identity_id  uuid NOT NULL,
  decision_id  uuid NOT NULL,
  call_digest  text NOT NULL,
  tool_kind    text NOT NULL,
  issued_at    timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz NOT NULL,
  consumed_at  timestamptz,
  consumed_by  text
);
CREATE INDEX IF NOT EXISTS tool_call_tickets_expiry ON tool_call_tickets (expires_at);

-- ---- Behaviour monitoring ------------------------------------------------------

CREATE INDEX IF NOT EXISTS firewall_decisions_principal_time ON firewall_decisions (tenant_id, principal_id, occurred_at DESC);

-- Each agent's learned normal behaviour. Recomputed from its own history.
CREATE TABLE IF NOT EXISTS agent_behavior_profiles (
  tenant_id   text NOT NULL,
  identity_id uuid NOT NULL,
  computed_at timestamptz NOT NULL,
  events      integer NOT NULL,
  profile     jsonb NOT NULL,
  PRIMARY KEY (tenant_id, identity_id)
);

-- Current classification per agent, plus the review cursor.
CREATE TABLE IF NOT EXISTS agent_behavior_state (
  tenant_id       text NOT NULL,
  identity_id     uuid NOT NULL,
  level           text NOT NULL CHECK (level IN ('NORMAL', 'SUSPICIOUS', 'HIGH_RISK', 'CRITICAL')),
  score           integer NOT NULL,
  signals         jsonb NOT NULL,
  assessed_at     timestamptz NOT NULL,
  window_start    timestamptz,
  acknowledged_at timestamptz,
  acknowledged_by text,
  excluded_from   timestamptz,
  excluded_to     timestamptz,
  PRIMARY KEY (tenant_id, identity_id)
);

-- Every level change, review and automatic containment. Append-only, hash-chained.
CREATE TABLE IF NOT EXISTS agent_behavior_events (
  seq           bigserial PRIMARY KEY,
  chain_key     text NOT NULL,
  event_id      uuid NOT NULL UNIQUE,
  occurred_at   timestamptz NOT NULL,
  tenant_id     text NOT NULL,
  identity_id   text NOT NULL,
  identity_name text NOT NULL,
  kind          text NOT NULL CHECK (kind IN ('level_change', 'acknowledged', 'auto_suspended')),
  from_level    text NOT NULL,
  to_level      text NOT NULL,
  score         integer NOT NULL,
  signals       jsonb NOT NULL,
  actor         text NOT NULL,
  reason        text,
  prev_hash     text NOT NULL,
  hash          text NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS agent_behavior_events_chain ON agent_behavior_events (chain_key, seq);
CREATE INDEX IF NOT EXISTS agent_behavior_events_identity ON agent_behavior_events (tenant_id, identity_id, seq DESC);
DROP TRIGGER IF EXISTS agent_behavior_events_no_update ON agent_behavior_events;
CREATE TRIGGER agent_behavior_events_no_update
  BEFORE UPDATE OR DELETE ON agent_behavior_events
  FOR EACH ROW EXECUTE FUNCTION principal_audit_log_append_only();
DROP TRIGGER IF EXISTS agent_behavior_events_no_truncate ON agent_behavior_events;
CREATE TRIGGER agent_behavior_events_no_truncate
  BEFORE TRUNCATE ON agent_behavior_events
  FOR EACH STATEMENT EXECUTE FUNCTION principal_audit_log_append_only();

-- ---- Emergency kill switch ------------------------------------------------------

-- Cut-off markers: what a suspension withdrew, and when.
ALTER TABLE tool_call_tickets ADD COLUMN IF NOT EXISTS revoked_at timestamptz;
ALTER TABLE agent_messages ADD COLUMN IF NOT EXISTS withdrawn_at timestamptz;

-- Every suspension or revocation of an agent, with who, why and what was cut
-- off. Evidence: append-only and hash-chained per tenant.
CREATE TABLE IF NOT EXISTS security_events (
  seq           bigserial PRIMARY KEY,
  chain_key     text NOT NULL,
  event_id      uuid NOT NULL UNIQUE,
  occurred_at   timestamptz NOT NULL,
  tenant_id     text NOT NULL,
  kind          text NOT NULL CHECK (kind IN ('agent_killed', 'agent_suspended', 'agent_revoked', 'agent_auto_suspended')),
  severity      text NOT NULL CHECK (severity IN ('medium', 'high', 'critical')),
  identity_id   text NOT NULL,
  identity_kind text NOT NULL,
  identity_name text NOT NULL,
  actor_type    text NOT NULL,
  actor_id      text NOT NULL,
  compromise    text NOT NULL CHECK (compromise IN ('none', 'suspected', 'confirmed')),
  reason        text,
  details       jsonb NOT NULL,
  prev_hash     text NOT NULL,
  hash          text NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS security_events_chain ON security_events (chain_key, seq);
CREATE INDEX IF NOT EXISTS security_events_identity ON security_events (tenant_id, identity_id, seq DESC);
DROP TRIGGER IF EXISTS security_events_no_update ON security_events;
CREATE TRIGGER security_events_no_update
  BEFORE UPDATE OR DELETE ON security_events
  FOR EACH ROW EXECUTE FUNCTION principal_audit_log_append_only();
DROP TRIGGER IF EXISTS security_events_no_truncate ON security_events;
CREATE TRIGGER security_events_no_truncate
  BEFORE TRUNCATE ON security_events
  FOR EACH STATEMENT EXECUTE FUNCTION principal_audit_log_append_only();

-- Administrator notifications (outbox). Written in the same transaction as
-- the suspension, so a notice cannot be lost between "suspended" and "sent".
CREATE TABLE IF NOT EXISTS security_notifications (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       text NOT NULL,
  event_ids       uuid[] NOT NULL,
  subject         text NOT NULL,
  body            jsonb NOT NULL,
  status          text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'sent', 'failed', 'undeliverable')),
  attempts        integer NOT NULL DEFAULT 0,
  created_at      timestamptz NOT NULL DEFAULT now(),
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  sent_at         timestamptz,
  last_error      text
);
CREATE INDEX IF NOT EXISTS security_notifications_due ON security_notifications (next_attempt_at) WHERE status IN ('pending', 'failed');
CREATE INDEX IF NOT EXISTS security_notifications_tenant ON security_notifications (tenant_id, created_at DESC);

-- ---- Agent-to-agent trust ----------------------------------------------------------

-- Every relayed request carries its interaction (the root request's id), its
-- parent, its hop, the authority it runs under, and optionally the one
-- resource it is about.
ALTER TABLE agent_messages ADD COLUMN IF NOT EXISTS interaction_id uuid;
ALTER TABLE agent_messages ADD COLUMN IF NOT EXISTS parent_message_id uuid;
ALTER TABLE agent_messages ADD COLUMN IF NOT EXISTS hop integer NOT NULL DEFAULT 1;
ALTER TABLE agent_messages ADD COLUMN IF NOT EXISTS authority jsonb;
ALTER TABLE agent_messages ADD COLUMN IF NOT EXISTS resource_type text;
ALTER TABLE agent_messages ADD COLUMN IF NOT EXISTS resource_id text;
ALTER TABLE agent_messages ADD COLUMN IF NOT EXISTS read_at timestamptz;
CREATE INDEX IF NOT EXISTS agent_messages_interaction ON agent_messages (interaction_id);
CREATE INDEX IF NOT EXISTS agent_messages_parent ON agent_messages (parent_message_id);
CREATE INDEX IF NOT EXISTS agent_messages_read ON agent_messages (tenant_id, to_identity, read_at DESC) WHERE read_at IS NOT NULL;

-- A person may allow an agent to pass their authority on to other agents.
ALTER TABLE agent_delegations ADD COLUMN IF NOT EXISTS redelegable boolean NOT NULL DEFAULT false;

-- The interaction chain, for investigation: every request sent or refused,
-- read, acted on or refused, and every hidden delegation stopped.
-- Append-only and hash-chained per tenant.
CREATE TABLE IF NOT EXISTS agent_interactions (
  seq                bigserial PRIMARY KEY,
  chain_key          text NOT NULL,
  event_id           uuid NOT NULL UNIQUE,
  occurred_at        timestamptz NOT NULL,
  tenant_id          text NOT NULL,
  kind               text NOT NULL CHECK (kind IN ('request_sent', 'request_blocked', 'request_read', 'acted', 'act_blocked', 'hidden_delegation_blocked')),
  interaction_id     uuid,
  message_id         uuid,
  parent_message_id  uuid,
  hop                integer NOT NULL,
  source_agent       text NOT NULL,
  destination_agent  text NOT NULL,
  actor_id           text NOT NULL,
  action             text NOT NULL,
  requested_permission text,
  resource           text,
  authority          jsonb NOT NULL,
  agent_chain        text[] NOT NULL,
  decision           text NOT NULL,
  decision_id        uuid,
  rule_ids           text[] NOT NULL,
  prev_hash          text NOT NULL,
  hash               text NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS agent_interactions_chain ON agent_interactions (chain_key, seq);
CREATE INDEX IF NOT EXISTS agent_interactions_interaction ON agent_interactions (tenant_id, interaction_id, seq);
CREATE INDEX IF NOT EXISTS agent_interactions_edges ON agent_interactions (tenant_id, source_agent, destination_agent);
DROP TRIGGER IF EXISTS agent_interactions_no_update ON agent_interactions;
CREATE TRIGGER agent_interactions_no_update
  BEFORE UPDATE OR DELETE ON agent_interactions
  FOR EACH ROW EXECUTE FUNCTION principal_audit_log_append_only();
DROP TRIGGER IF EXISTS agent_interactions_no_truncate ON agent_interactions;
CREATE TRIGGER agent_interactions_no_truncate
  BEFORE TRUNCATE ON agent_interactions
  FOR EACH STATEMENT EXECUTE FUNCTION principal_audit_log_append_only();

-- Point-in-time copies of the trust graph with their hash, so what the graph
-- showed on a given day can be proven later. Append-only, hash-chained.
CREATE TABLE IF NOT EXISTS agent_trust_graph_snapshots (
  seq          bigserial PRIMARY KEY,
  chain_key    text NOT NULL,
  snapshot_id  uuid NOT NULL UNIQUE,
  occurred_at  timestamptz NOT NULL,
  tenant_id    text NOT NULL,
  taken_by     text NOT NULL,
  note         text,
  graph_hash   text NOT NULL,
  graph        jsonb NOT NULL,
  prev_hash    text NOT NULL,
  hash         text NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS agent_trust_graph_snapshots_chain ON agent_trust_graph_snapshots (chain_key, seq);
DROP TRIGGER IF EXISTS agent_trust_graph_snapshots_no_update ON agent_trust_graph_snapshots;
CREATE TRIGGER agent_trust_graph_snapshots_no_update
  BEFORE UPDATE OR DELETE ON agent_trust_graph_snapshots
  FOR EACH ROW EXECUTE FUNCTION principal_audit_log_append_only();
DROP TRIGGER IF EXISTS agent_trust_graph_snapshots_no_truncate ON agent_trust_graph_snapshots;
CREATE TRIGGER agent_trust_graph_snapshots_no_truncate
  BEFORE TRUNCATE ON agent_trust_graph_snapshots
  FOR EACH STATEMENT EXECUTE FUNCTION principal_audit_log_append_only();
`;

/** Constant advisory-lock key, so concurrently starting instances migrate one at a time. */
const MIGRATION_LOCK = 734_011_902;

export async function migrate(pool: Pool): Promise<void> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT pg_advisory_xact_lock($1)", [MIGRATION_LOCK]);
    await client.query(SCHEMA_SQL);
    await client.query("COMMIT");
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}
