-- F-02 (PR-2): erasure of audit evidence is bounded by the database, not by the API.
--
-- Before: any session could set legion.audit_erasure = 'on' and then delete or rewrite
-- audit rows of any age. Now an append-only row may only be removed when
-- legion_erasure_allowed() says so (agent schema): inside one of the functions below,
-- or — single-role installs only — by a session whose login role owns the table.
--
-- The functions run as their owner (SECURITY DEFINER). With the owner/runtime split
-- (db/provision.ts, DB_ROLE_SPLIT) that owner is legion_owner and the API's role can
-- only call them, so what the API can erase is exactly what they allow:
--   legion_pseudonymise_audit  audit_log: remove email/IP from entries older than the
--                              retention period, never younger than 30 days
--   legion_prune_chain         the oldest rows of one agent log chain, older than the
--                              period (never younger than 30 days); the newest row
--                              always stays and the last removed hash is anchored
--   legion_prune_soc           finished SOC history older than the period (at least
--                              30 days); pending/running work is never touched; the
--                              audit chain keeps an anchor and its newest event
--   legion_erase_tenant        one whole workspace, refused under a legal hold unless
--                              forced, and always recorded in tenant_deletions
-- A workspace on a legal hold is skipped by every retention function.

CREATE OR REPLACE FUNCTION legion_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF legion_erasure_allowed(TG_RELID) THEN
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
  END IF;
  RAISE EXCEPTION '% is append-only (% refused)', TG_TABLE_NAME, TG_OP USING ERRCODE = 'insufficient_privilege';
END $$;

-- The earliest moment a retention function may reach: the period asked for, but never
-- less than 30 days ago (a wrong setting or a compromised caller cannot erase recent evidence).
CREATE OR REPLACE FUNCTION legion_retention_cutoff(p_months int, p_days int) RETURNS timestamptz
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF coalesce(p_months, 0) < 0 OR coalesce(p_days, 0) < 0 OR (coalesce(p_months, 0) = 0 AND coalesce(p_days, 0) = 0) THEN
    RAISE EXCEPTION 'retention period must be positive' USING ERRCODE = 'invalid_parameter_value';
  END IF;
  RETURN least(now() - make_interval(months => coalesce(p_months, 0), days => coalesce(p_days, 0)), now() - interval '30 days');
END $$;

CREATE OR REPLACE FUNCTION legion_pseudonymise_audit(p_tenant uuid, p_months int) RETURNS int
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE cutoff timestamptz := legion_retention_cutoff(p_months, 0); n int;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM tenants WHERE id = p_tenant AND NOT legal_hold) THEN RETURN 0; END IF;
  PERFORM legion_erasure_begin('pseudonymise_audit');
  UPDATE audit_log
     SET user_email = NULL, ip_address = NULL,
         detail = CASE WHEN detail IS NULL THEN NULL ELSE regexp_replace(detail, '[[:alnum:]._%+-]+@[[:alnum:].-]+', '[removed]', 'g') END
   WHERE tenant_id = p_tenant AND created_at < cutoff
     AND (user_email IS NOT NULL OR ip_address IS NOT NULL OR detail ~ '[[:alnum:]._%+-]+@[[:alnum:].-]+');
  GET DIAGNOSTICS n = ROW_COUNT;
  PERFORM legion_erasure_end();
  RETURN n;
END $$;

CREATE OR REPLACE FUNCTION legion_prune_chain(p_table text, p_tenant uuid, p_months int) RETURNS int
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE cutoff timestamptz := legion_retention_cutoff(p_months, 0); boundary bigint; last_seq bigint; last_hash text; n int := 0;
BEGIN
  IF p_table IS NULL OR p_table <> ALL (ARRAY['principal_audit_log', 'firewall_decisions', 'content_ingestion_log', 'tool_call_audit']) THEN
    RAISE EXCEPTION 'not a prunable chain: %', p_table USING ERRCODE = 'invalid_parameter_value';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM tenants WHERE id = p_tenant AND NOT legal_hold) THEN RETURN 0; END IF;
  -- The lock the writers of this chain take: nothing is appended mid-prune.
  PERFORM pg_advisory_xact_lock(hashtextextended(p_table || ':' || p_tenant::text, 0));
  -- First row still inside the window; if every row is old, keep the newest one.
  EXECUTE format('SELECT coalesce((SELECT min(seq) FROM %I WHERE chain_key = $1 AND occurred_at >= $2), (SELECT max(seq) FROM %I WHERE chain_key = $1))', p_table, p_table)
    INTO boundary USING p_tenant::text, cutoff;
  IF boundary IS NULL THEN RETURN 0; END IF;
  EXECUTE format('SELECT seq, hash FROM %I WHERE chain_key = $1 AND seq < $2 ORDER BY seq DESC LIMIT 1', p_table)
    INTO last_seq, last_hash USING p_tenant::text, boundary;
  IF last_seq IS NULL THEN RETURN 0; END IF;
  PERFORM legion_erasure_begin('prune_chain');
  EXECUTE format('DELETE FROM %I WHERE chain_key = $1 AND seq < $2', p_table) USING p_tenant::text, boundary;
  GET DIAGNOSTICS n = ROW_COUNT;
  INSERT INTO chain_prune_anchors (table_name, tenant_id, anchor_hash, pruned_through_seq, pruned_rows)
  VALUES (p_table, p_tenant::text, last_hash, last_seq, n)
  ON CONFLICT (table_name, tenant_id) DO UPDATE
    SET anchor_hash = EXCLUDED.anchor_hash, pruned_through_seq = EXCLUDED.pruned_through_seq,
        pruned_rows = chain_prune_anchors.pruned_rows + EXCLUDED.pruned_rows, pruned_at = now();
  PERFORM legion_erasure_end();
  RETURN n;
END $$;

CREATE OR REPLACE FUNCTION legion_prune_soc(p_tenant uuid, p_days int) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
  cutoff timestamptz := legion_retention_cutoff(0, p_days);
  -- Finished action states (retention.ts SOC_TERMINAL_ACTIONS). Fixed here, not passed in,
  -- so a caller cannot widen it to pending work.
  terminal text[] := ARRAY['denied', 'recorded', 'rejected', 'expired', 'cancelled', 'simulated', 'failed'];
  c jsonb := '{"soc_jobs":0,"action_requests":0,"approval_requests":0,"policy_decisions":0,"workflow_runs":0,"soc_audit_events":0}';
  n int; boundary bigint; last_seq bigint; last_hash text;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM tenants WHERE id = p_tenant AND NOT legal_hold) THEN RETURN c; END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('soc_retention:' || p_tenant::text, 0));
  PERFORM legion_erasure_begin('prune_soc');
  DELETE FROM soc_jobs WHERE tenant_id = p_tenant AND status IN ('done', 'dead') AND coalesce(finished_at, updated_at) < cutoff;
  GET DIAGNOSTICS n = ROW_COUNT; c := jsonb_set(c, '{soc_jobs}', to_jsonb(n));
  -- Cascades to action_events.
  DELETE FROM action_requests WHERE tenant_id = p_tenant AND status = ANY (terminal) AND created_at < cutoff;
  GET DIAGNOSTICS n = ROW_COUNT; c := jsonb_set(c, '{action_requests}', to_jsonb(n));
  -- Only approvals no surviving action still points at (the foreign key has no cascade, on purpose).
  DELETE FROM approval_requests a WHERE a.tenant_id = p_tenant AND a.status <> 'pending' AND a.created_at < cutoff
     AND NOT EXISTS (SELECT 1 FROM action_requests r WHERE r.tenant_id = a.tenant_id AND r.approval_id = a.id);
  GET DIAGNOSTICS n = ROW_COUNT; c := jsonb_set(c, '{approval_requests}', to_jsonb(n));
  DELETE FROM policy_decisions WHERE tenant_id = p_tenant AND created_at < cutoff;
  GET DIAGNOSTICS n = ROW_COUNT; c := jsonb_set(c, '{policy_decisions}', to_jsonb(n));
  DELETE FROM workflow_runs WHERE tenant_id = p_tenant AND status <> 'running' AND coalesce(finished_at, created_at) < cutoff;
  GET DIAGNOSTICS n = ROW_COUNT; c := jsonb_set(c, '{workflow_runs}', to_jsonb(n));

  -- Audit events: the first event still inside the window; if all are old, keep the newest one.
  SELECT coalesce((SELECT min(seq) FROM soc_audit_events WHERE tenant_id = p_tenant AND at >= cutoff),
                  (SELECT max(seq) FROM soc_audit_events WHERE tenant_id = p_tenant)) INTO boundary;
  IF boundary IS NOT NULL THEN
    SELECT seq, hash INTO last_seq, last_hash FROM soc_audit_events WHERE tenant_id = p_tenant AND seq < boundary ORDER BY seq DESC LIMIT 1;
    IF last_seq IS NOT NULL THEN
      DELETE FROM soc_audit_events WHERE tenant_id = p_tenant AND seq < boundary;
      GET DIAGNOSTICS n = ROW_COUNT; c := jsonb_set(c, '{soc_audit_events}', to_jsonb(n));
      INSERT INTO chain_prune_anchors (table_name, tenant_id, anchor_hash, pruned_through_seq, pruned_rows)
      VALUES ('soc_audit_events', p_tenant::text, last_hash, last_seq, n)
      ON CONFLICT (table_name, tenant_id) DO UPDATE
        SET anchor_hash = EXCLUDED.anchor_hash, pruned_through_seq = EXCLUDED.pruned_through_seq,
            pruned_rows = chain_prune_anchors.pruned_rows + EXCLUDED.pruned_rows, pruned_at = now();
    END IF;
  END IF;
  PERFORM legion_erasure_end();
  RETURN c;
END $$;

CREATE OR REPLACE FUNCTION legion_erase_tenant(p_tenant uuid, p_by text, p_reason text, p_counts jsonb, p_force boolean) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE hold boolean; pending text[]; stuck text[]; t text;
BEGIN
  SELECT legal_hold INTO hold FROM tenants WHERE id = p_tenant FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'no such workspace' USING ERRCODE = 'no_data_found'; END IF;
  IF hold AND NOT coalesce(p_force, false) THEN
    RAISE EXCEPTION 'the workspace is on a legal hold' USING ERRCODE = 'insufficient_privilege';
  END IF;
  PERFORM legion_erasure_begin('erase_tenant');
  -- Tables without a foreign key to tenants (the agent layer) and any with one: try each,
  -- and retry the ones a foreign key held back until a pass makes no progress.
  SELECT coalesce(array_agg(c.table_name::text ORDER BY c.table_name), '{}') INTO pending
    FROM information_schema.columns c
    JOIN information_schema.tables x ON x.table_schema = c.table_schema AND x.table_name = c.table_name AND x.table_type = 'BASE TABLE'
   WHERE c.table_schema = 'public' AND c.column_name = 'tenant_id'
     AND c.table_name NOT IN ('tenants', 'users', 'tenant_deletions');
  WHILE cardinality(pending) > 0 LOOP
    stuck := '{}';
    FOREACH t IN ARRAY pending LOOP
      BEGIN
        EXECUTE format('DELETE FROM %I WHERE tenant_id::text = $1', t) USING p_tenant::text;
      EXCEPTION WHEN foreign_key_violation THEN
        stuck := stuck || t;
      END;
    END LOOP;
    EXIT WHEN cardinality(stuck) = cardinality(pending);
    pending := stuck;
  END LOOP;
  DELETE FROM users WHERE tenant_id = p_tenant;
  DELETE FROM tenants WHERE id = p_tenant;
  INSERT INTO tenant_deletions (tenant_id, deleted_by, reason, counts)
  VALUES (p_tenant, left(coalesce(p_by, 'unknown'), 80), left(p_reason, 300), coalesce(p_counts, '{}'));
  PERFORM legion_erasure_end();
END $$;
