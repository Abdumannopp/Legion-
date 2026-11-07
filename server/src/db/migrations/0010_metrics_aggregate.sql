-- F-04 follow-up: /metrics counts SOC state across every workspace (counts only, grouped by workspace).
-- Under row-level security (DB_RLS=enforce) the API's role cannot read across workspaces, by design, so
-- the aggregate runs here, as the owner: the API gets numbers, never rows. Also reports the database's
-- size, so a growing disk is visible before it is full.

CREATE OR REPLACE FUNCTION legion_soc_metrics(p_running_stale_seconds int) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
  SELECT jsonb_build_object(
    'jobs', (SELECT coalesce(jsonb_agg(x), '[]') FROM (SELECT tenant_id, status AS k, count(*)::int AS n FROM soc_jobs GROUP BY tenant_id, status) x),
    'job_ages', (SELECT coalesce(jsonb_agg(x), '[]') FROM (SELECT tenant_id,
        coalesce(floor(extract(epoch FROM now() - min(run_after) FILTER (WHERE status = 'queued' AND run_after <= now()))), 0)::int AS oldest_due,
        count(*) FILTER (WHERE status = 'running' AND lease_until < now())::int AS expired_leases
      FROM soc_jobs GROUP BY tenant_id) x),
    'actions', (SELECT coalesce(jsonb_agg(x), '[]') FROM (SELECT tenant_id, status AS k, count(*)::int AS n FROM action_requests GROUP BY tenant_id, status) x),
    'act', (SELECT coalesce(jsonb_agg(x), '[]') FROM (SELECT tenant_id,
        count(*) FILTER (WHERE execution_mode NOT IN ('shadow', 'simulation'))::int AS live,
        count(*) FILTER (WHERE status = 'running' AND updated_at < now() - make_interval(secs => p_running_stale_seconds))::int AS stuck
      FROM action_requests GROUP BY tenant_id) x),
    'appr', (SELECT coalesce(jsonb_agg(x), '[]') FROM (SELECT tenant_id,
        count(*) FILTER (WHERE status = 'pending' AND expires_at > now())::int AS pending,
        coalesce(floor(extract(epoch FROM now() - min(created_at) FILTER (WHERE status = 'pending' AND expires_at > now()))), 0)::int AS oldest,
        count(*) FILTER (WHERE status = 'approved')::int AS approved_unused
      FROM approval_requests GROUP BY tenant_id) x),
    'paused', (SELECT coalesce(jsonb_agg(x), '[]') FROM (SELECT tenant_id, count(*)::int AS n FROM soc_controls WHERE actions_paused GROUP BY tenant_id) x),
    'pol', (SELECT coalesce(jsonb_agg(x), '[]') FROM (SELECT tenant_id, decision AS k, count(*)::int AS n FROM policy_decisions
        WHERE created_at > now() - interval '5 minutes' GROUP BY tenant_id, decision) x),
    'div', (SELECT coalesce(jsonb_agg(x), '[]') FROM (SELECT tenant_id, count(*)::int AS n FROM policy_decisions
        WHERE created_at > now() - interval '24 hours' AND enforcement = 'shadow' AND decision <> 'ALLOW' AND legacy_outcome IS NOT NULL AND legacy_outcome NOT LIKE 'skipped%'
        GROUP BY tenant_id) x),
    'audit', (SELECT coalesce(jsonb_agg(x), '[]') FROM (SELECT tenant_id, count(*)::int AS n FROM soc_audit_events GROUP BY tenant_id) x),
    'heads', (SELECT coalesce(jsonb_agg(x), '[]') FROM (SELECT DISTINCT ON (tenant_id) tenant_id, key_id FROM soc_audit_events ORDER BY tenant_id, seq DESC) x),
    'wf', (SELECT coalesce(jsonb_agg(x), '[]') FROM (SELECT tenant_id, count(*) FILTER (WHERE status = 'failed')::int AS failed, count(*)::int AS total
        FROM workflow_runs WHERE created_at > now() - interval '1 hour' GROUP BY tenant_id) x),
    'db_bytes', pg_database_size(current_database())
  )
$$;
