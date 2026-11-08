-- Audit A-4: how far behind are the polls? Counts and one age only (no workspace data), for /metrics.
-- Runs as the owner because integration_connections is under row-level security (0014) and /metrics
-- looks across workspaces.
CREATE OR REPLACE FUNCTION legion_integration_lag(p_kinds text[]) RETURNS TABLE (status text, n bigint, overdue_seconds bigint)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
  SELECT status, count(*),
         coalesce(floor(extract(epoch FROM now() - min(next_poll_at) FILTER (WHERE status = 'active' AND next_poll_at <= now() AND kind = ANY(p_kinds))))::bigint, 0)
    FROM integration_connections WHERE status <> 'disabled' GROUP BY status
$$;
