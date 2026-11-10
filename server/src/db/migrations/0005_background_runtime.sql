-- Task 10, module 5: Background Runtime.
--
-- One durable job queue for the SOC core. A job is enqueued in the same
-- transaction as the state change that needs it (no lost work after a crash),
-- claimed with SKIP LOCKED and a lease, and finished only by the worker that
-- holds the lease (fenced by owner and attempt number). Failing jobs back off;
-- after max_attempts they are dead and kept for inspection.

CREATE TABLE soc_jobs (
  tenant_id    uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  id           uuid        NOT NULL,
  kind         text        NOT NULL CHECK (kind IN ('action.run', 'workflow.run')),
  payload      jsonb       NOT NULL CHECK (octet_length(payload::text) <= 8192),
  dedupe_key   text        NOT NULL CHECK (length(dedupe_key) BETWEEN 1 AND 200),
  status       text        NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'done', 'dead')),
  attempts     int         NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  max_attempts int         NOT NULL DEFAULT 5 CHECK (max_attempts BETWEEN 1 AND 20),
  run_after    timestamptz NOT NULL DEFAULT now(),
  lease_owner  text,
  lease_until  timestamptz,
  last_error   text        CHECK (last_error IS NULL OR length(last_error) <= 500),
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now(),
  finished_at  timestamptz,
  PRIMARY KEY (tenant_id, id),
  -- The same work is never queued twice.
  UNIQUE (tenant_id, kind, dedupe_key),
  CHECK (status <> 'running' OR (lease_owner IS NOT NULL AND lease_until IS NOT NULL))
);
CREATE INDEX soc_jobs_due_idx ON soc_jobs (run_after) WHERE status IN ('queued', 'running');
CREATE INDEX soc_jobs_tenant_status_idx ON soc_jobs (tenant_id, status);
