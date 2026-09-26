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
