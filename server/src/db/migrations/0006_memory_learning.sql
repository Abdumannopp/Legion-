-- Task 10, module 7: Memory and Learning foundation.
--
-- Memory: short facts people record about things Legion sees (this address is
-- our scanner, this alert rule is noisy). Written by people or by Legion's own
-- deterministic code — never by a language model. Every entry expires.
--
-- Learning: counts of how people decided on agents' proposals, per action.
-- They feed suggestions a person may act on; nothing changes by itself.

CREATE TABLE soc_memory (
  tenant_id    uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  id           uuid        NOT NULL,
  kind         text        NOT NULL CHECK (kind IN ('note', 'false_positive', 'known_benign')),
  subject_type text        NOT NULL CHECK (subject_type IN ('ip', 'host', 'account', 'alert_title')),
  subject_key  text        NOT NULL CHECK (length(subject_key) BETWEEN 1 AND 200),
  content      text        NOT NULL CHECK (length(content) BETWEEN 1 AND 2000),
  source       text        NOT NULL CHECK (source IN ('human', 'system')),
  created_by   uuid,
  created_at   timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, id),
  CHECK (expires_at > created_at AND expires_at <= created_at + interval '366 days')
);
CREATE INDEX soc_memory_subject_idx ON soc_memory (tenant_id, subject_type, subject_key);
CREATE INDEX soc_memory_expiry_idx ON soc_memory (expires_at);

CREATE TABLE learning_signals (
  tenant_id  uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  action_id  text        NOT NULL CHECK (length(action_id) <= 64),
  signal     text        NOT NULL CHECK (signal IN ('approved', 'rejected', 'expired', 'cancelled')),
  count      bigint      NOT NULL DEFAULT 0 CHECK (count >= 0),
  last_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, action_id, signal)
);
