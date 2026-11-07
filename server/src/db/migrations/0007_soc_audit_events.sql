-- Task 10, module 8: audit and observability.
--
-- One append-only event stream for the SOC core, per workspace, chained with
-- a keyed hash (HMAC-SHA256): each event's hash covers the previous one, so a
-- changed, removed or inserted event is detectable by anyone holding the key —
-- and cannot be re-chained by someone who only has database access.

CREATE TABLE soc_audit_events (
  tenant_id    uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  seq          bigint      NOT NULL CHECK (seq > 0),
  id           uuid        NOT NULL,
  at           timestamptz NOT NULL DEFAULT now(),
  category     text        NOT NULL CHECK (category IN ('policy', 'approval', 'action', 'workflow', 'runtime', 'memory', 'controls')),
  event        text        NOT NULL CHECK (event ~ '^[a-z_]{1,32}\.[a-z_]{1,32}$'),
  actor        jsonb       NOT NULL,
  subject_type text        CHECK (subject_type IS NULL OR subject_type ~ '^[a-z_]{1,32}$'),
  subject_id   text        CHECK (subject_id IS NULL OR length(subject_id) <= 100),
  detail       jsonb       NOT NULL DEFAULT '{}' CHECK (octet_length(detail::text) <= 4096),
  key_id       text        NOT NULL CHECK (key_id ~ '^[a-z0-9_-]{1,32}$'),
  prev_hash    text        NOT NULL CHECK (prev_hash ~ '^[0-9a-f]{64}$'),
  hash         text        NOT NULL CHECK (hash ~ '^[0-9a-f]{64}$'),
  PRIMARY KEY (tenant_id, seq),
  UNIQUE (tenant_id, id)
);
CREATE INDEX soc_audit_events_tenant_at_idx ON soc_audit_events (tenant_id, at DESC);
CREATE TRIGGER soc_audit_events_append_only
  BEFORE UPDATE OR DELETE ON soc_audit_events
  FOR EACH ROW EXECUTE FUNCTION legion_append_only();
