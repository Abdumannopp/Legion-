-- F-04 (PR-3a): row-level security for the tables Legion only ever reaches workspace-first
-- (db/rls.ts RLS_TABLES — the MUST_SCOPE set of the tenant-query guard).
--
-- The policy shows and accepts a row only when its tenant_id is the workspace the session
-- declared (legion.tenant_id) — but only in sessions that say the API runs with DB_RLS=enforce
-- (legion.rls = 'enforce', set by the API on each connection). Everything else (DB_RLS=off,
-- backups, operator tools) sees what it saw before. Without a declared workspace an enforcing
-- session sees nothing and can write nothing: fail closed.
--
-- Row-level security never binds a table's owner (no FORCE): the bounded erasure functions
-- (0008), which run as the owner, keep working across workspaces, and a single-role install,
-- whose API owns the tables, is unaffected. It binds the API under the owner/runtime split.
-- Foreign-key checks are not subject to it.

CREATE OR REPLACE FUNCTION legion_rls_tenant_ok(t uuid) RETURNS boolean
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT coalesce(current_setting('legion.rls', true), '') <> 'enforce'
      OR t = nullif(current_setting('legion.tenant_id', true), '')::uuid
$$;

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'alerts', 'assets', 'audit_log',
    'policy_documents', 'policy_active', 'policy_decisions',
    'approval_requests', 'approval_decisions', 'action_requests', 'action_events',
    'soc_controls', 'workflow_runs', 'learning_signals', 'soc_audit_events'
  ] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('DROP POLICY IF EXISTS legion_tenant_isolation ON %I', t);
    EXECUTE format('CREATE POLICY legion_tenant_isolation ON %I USING (legion_rls_tenant_ok(tenant_id)) WITH CHECK (legion_rls_tenant_ok(tenant_id))', t);
  END LOOP;
END $$;
