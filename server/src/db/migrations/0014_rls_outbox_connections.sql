-- Audit A-3 (2026-11-08): notification_outbox and integration_connections join the row-level security
-- of 0009. Both hold one workspace's data (alert text and recipients; integration settings and sealed
-- credentials); until now only application code kept workspaces apart there.
--
-- The background workers must still see every workspace's due work to pick it up. They do that only
-- through the bounded SECURITY DEFINER functions below (run as the owner, whom row-level security does
-- not bind); each returns exactly the rows a worker claims, and everything the worker then does with a
-- row runs inside that row's own workspace context (db/rls.ts withTenant), so it is checked again.

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['notification_outbox', 'integration_connections'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('DROP POLICY IF EXISTS legion_tenant_isolation ON %I', t);
    EXECUTE format('CREATE POLICY legion_tenant_isolation ON %I USING (legion_rls_tenant_ok(tenant_id)) WITH CHECK (legion_rls_tenant_ok(tenant_id))', t);
  END LOOP;
END $$;

-- Outbox: claim due rows of any workspace (pending and due, or in flight with an expired lease and attempts left).
CREATE OR REPLACE FUNCTION legion_outbox_claim(p_limit int, p_lease_seconds int, p_kind text)
RETURNS TABLE (id uuid, tenant_id uuid, kind text, recipient text, payload jsonb, attempts int, max_attempts int)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = public, pg_temp AS $$
  UPDATE notification_outbox o SET status = 'sending', attempts = o.attempts + 1,
         locked_until = now() + make_interval(secs => p_lease_seconds)
   WHERE o.id IN (
     SELECT x.id FROM notification_outbox x
      WHERE ((x.status = 'pending' AND x.next_attempt_at <= now())
          OR (x.status = 'sending' AND x.locked_until < now() AND x.attempts < x.max_attempts))
        AND (p_kind IS NULL OR x.kind = p_kind)
      ORDER BY x.next_attempt_at
      LIMIT least(greatest(p_limit, 1), 500)
      FOR UPDATE SKIP LOCKED)
  RETURNING o.id, o.tenant_id, o.kind, o.recipient, o.payload, o.attempts, o.max_attempts
$$;

-- Outbox: a row whose worker died during its final attempt is dead-lettered (never re-sent).
CREATE OR REPLACE FUNCTION legion_outbox_dead_abandoned(p_kind text) RETURNS SETOF uuid
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = public, pg_temp AS $$
  UPDATE notification_outbox SET status = 'dead', locked_until = NULL,
         last_error = 'worker stopped during the final attempt; outcome unknown'
   WHERE status = 'sending' AND locked_until < now() AND attempts >= max_attempts
     AND (p_kind IS NULL OR kind = p_kind)
  RETURNING id
$$;

-- Outbox: retention of delivered rows (counts only).
CREATE OR REPLACE FUNCTION legion_outbox_prune_realtime() RETURNS int
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = public, pg_temp AS $$
  WITH d AS (DELETE FROM notification_outbox WHERE kind = 'realtime_alert' AND status = 'sent' AND sent_at < now() - interval '1 day' RETURNING 1)
  SELECT count(*)::int FROM d
$$;
CREATE OR REPLACE FUNCTION legion_outbox_prune_delivered(p_days int) RETURNS int
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = public, pg_temp AS $$
  WITH d AS (DELETE FROM notification_outbox WHERE kind IN ('alert_email', 'protection_email', 'integration_message')
              AND status = 'sent' AND sent_at < now() - make_interval(days => greatest(p_days, 1)) RETURNING 1)
  SELECT count(*)::int FROM d
$$;

-- Outbox: platform-wide queue health (counts per kind, no row data).
CREATE OR REPLACE FUNCTION legion_outbox_metrics()
RETURNS TABLE (kind text, pending bigint, retrying bigint, in_flight bigint, dead bigint, oldest numeric)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
  SELECT kind,
         count(*) FILTER (WHERE status = 'pending'),
         count(*) FILTER (WHERE status = 'pending' AND attempts > 0),
         count(*) FILTER (WHERE status = 'sending'),
         count(*) FILTER (WHERE status = 'dead'),
         floor(extract(epoch FROM now() - min(created_at) FILTER (WHERE status IN ('pending', 'sending'))))
    FROM notification_outbox WHERE status IN ('pending', 'sending', 'dead') GROUP BY kind
$$;

-- Integrations: the poll worker claims due pull connections of the workspaces this region serves.
CREATE OR REPLACE FUNCTION legion_connections_claim(p_limit int, p_lease_seconds int, p_owner text, p_region text, p_kinds text[])
RETURNS SETOF integration_connections
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = public, pg_temp AS $$
  UPDATE integration_connections SET lease_until = now() + make_interval(secs => p_lease_seconds), lease_owner = p_owner
   WHERE id IN (
     SELECT c.id FROM integration_connections c JOIN tenants t ON t.id = c.tenant_id
      WHERE c.status = 'active' AND c.next_poll_at <= now() AND (c.lease_until IS NULL OR c.lease_until < now())
        AND COALESCE(t.region, p_region) = p_region
        AND c.kind = ANY(p_kinds)
      ORDER BY c.next_poll_at LIMIT least(greatest(p_limit, 1), 100) FOR UPDATE OF c SKIP LOCKED)
  RETURNING *
$$;

-- Integrations: a GitHub delivery names its connection; before the signature is checked the workspace is not known.
-- Returns the one active GitHub connection with that id (its workspace and sealed secret), nothing else.
CREATE OR REPLACE FUNCTION legion_github_connection(p_id uuid)
RETURNS TABLE (id uuid, tenant_id uuid, secrets_enc text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
  SELECT id, tenant_id, secrets_enc FROM integration_connections WHERE id = p_id AND kind = 'github' AND status = 'active'
$$;
