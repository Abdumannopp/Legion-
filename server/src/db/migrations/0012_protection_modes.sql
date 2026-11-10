-- Protection modes (manual / hybrid / automatic): the user-permitted, bounded way for Legion to act on its own.
--
-- Default for every workspace: MANUAL, nothing runs live. A workspace administrator opts in (dashboard,
-- after confirming their password and accepting a written notice), and chooses which actions Legion may
-- take without asking (hybrid) or lets it take every action Legion can execute that is not critical (automatic).
--
-- The database holds the lines that code must not be able to cross by mistake:
--   * only the actions Legion has a real executor for can be pre-authorised (a list here: adding one
--     needs a new migration, like turning live on did);
--   * an action that an AI model produced never runs live without a person's approval;
--   * a critical (R4) action never runs without an approval, as before.

ALTER TABLE tenants ADD COLUMN IF NOT EXISTS protection_mode text NOT NULL DEFAULT 'manual'
  CHECK (protection_mode IN ('manual', 'hybrid', 'automatic'));
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS protection_auto_actions text[] NOT NULL DEFAULT '{}'
  CHECK (protection_auto_actions <@ ARRAY['ip.block', 'notify.admins']::text[]);
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS protection_ack_at timestamptz;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS protection_ack_by text;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS protection_ack_version text;
-- Turning protection on without a recorded acknowledgement is not possible, whatever the code does.
ALTER TABLE tenants ADD CONSTRAINT tenants_protection_ack_check
  CHECK (protection_mode = 'manual' OR protection_ack_at IS NOT NULL);

-- Notifications about what Legion did (or needs a person to decide).
ALTER TABLE notification_outbox DROP CONSTRAINT IF EXISTS notification_outbox_kind_check;
ALTER TABLE notification_outbox ADD CONSTRAINT notification_outbox_kind_check
  CHECK (kind IN ('alert_email', 'realtime_alert', 'protection_email'));

-- Live execution and its outcome.
ALTER TABLE workflow_runs DROP CONSTRAINT IF EXISTS workflow_runs_mode_check;
ALTER TABLE workflow_runs ADD CONSTRAINT workflow_runs_mode_check CHECK (mode IN ('shadow', 'simulation', 'live'));

ALTER TABLE action_requests DROP CONSTRAINT IF EXISTS action_requests_execution_mode_check;
ALTER TABLE action_requests ADD CONSTRAINT action_requests_execution_mode_check CHECK (execution_mode IN ('shadow', 'simulation', 'live'));
ALTER TABLE action_requests DROP CONSTRAINT IF EXISTS action_requests_status_check;
ALTER TABLE action_requests ADD CONSTRAINT action_requests_status_check CHECK (status IN
  ('denied', 'recorded', 'awaiting_approval', 'rejected', 'expired', 'cancelled', 'queued', 'running', 'simulated', 'executed', 'failed'));
-- Nothing the policy did not allow, or a person did not approve, ever runs.
ALTER TABLE action_requests DROP CONSTRAINT IF EXISTS action_requests_check;
ALTER TABLE action_requests ADD CONSTRAINT action_requests_check
  CHECK (status NOT IN ('queued', 'running', 'simulated', 'executed', 'failed') OR policy_decision = 'ALLOW' OR approval_id IS NOT NULL);
-- Critical actions run only with an approval, whoever asked.
ALTER TABLE action_requests DROP CONSTRAINT IF EXISTS action_requests_check1;
ALTER TABLE action_requests ADD CONSTRAINT action_requests_check1
  CHECK (risk_class <> 'R4' OR status NOT IN ('queued', 'running', 'simulated', 'executed', 'failed') OR approval_id IS NOT NULL);
-- A live action that an AI model produced is never on its own: a person approved it.
ALTER TABLE action_requests ADD CONSTRAINT action_requests_live_llm_check
  CHECK (execution_mode <> 'live' OR origin <> 'llm' OR status NOT IN ('queued', 'running', 'executed', 'failed') OR approval_id IS NOT NULL);

-- Retention: an executed action is finished history like any other (0008, with 'executed' added).
CREATE OR REPLACE FUNCTION legion_prune_soc(p_tenant uuid, p_days int) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
  cutoff timestamptz := legion_retention_cutoff(0, p_days);
  -- Finished action states (retention.ts SOC_TERMINAL_ACTIONS). Fixed here, not passed in,
  -- so a caller cannot widen it to pending work.
  terminal text[] := ARRAY['denied', 'recorded', 'rejected', 'expired', 'cancelled', 'simulated', 'executed', 'failed'];
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

