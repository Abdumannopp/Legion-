-- Dangerous-action control: erasing a workspace that is on a legal hold (only the ledger replay after
-- a restore passes p_force) now needs a written reason, and the tombstone records that the hold was
-- overridden. Same function as 0008 otherwise.

CREATE OR REPLACE FUNCTION legion_erase_tenant(p_tenant uuid, p_by text, p_reason text, p_counts jsonb, p_force boolean) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE hold boolean; pending text[]; stuck text[]; t text;
BEGIN
  SELECT legal_hold INTO hold FROM tenants WHERE id = p_tenant FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'no such workspace' USING ERRCODE = 'no_data_found'; END IF;
  IF hold AND NOT coalesce(p_force, false) THEN
    RAISE EXCEPTION 'the workspace is on a legal hold' USING ERRCODE = 'insufficient_privilege';
  END IF;
  -- Overriding a legal hold is never silent: it needs a written reason, and the tombstone says so.
  IF hold AND length(btrim(coalesce(p_reason, ''))) < 10 THEN
    RAISE EXCEPTION 'erasing a workspace on a legal hold needs a reason (at least 10 characters)' USING ERRCODE = 'insufficient_privilege';
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
  VALUES (p_tenant, left(coalesce(p_by, 'unknown'), 80), left(p_reason, 300),
          coalesce(p_counts, '{}') || CASE WHEN hold THEN '{"legal_hold_overridden": true}'::jsonb ELSE '{}'::jsonb END);
  PERFORM legion_erasure_end();
END $$;
