-- Task 10, module 2: Approval Engine v0.
--
-- An approval request is bound to ONE subject (an action request) and to the
-- digest of exactly what will be done. People decide; the request ends at
-- CONSUMED, which happens once, atomically, when the action engine uses it.

CREATE TABLE approval_requests (
  tenant_id          uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  id                 uuid        NOT NULL,
  subject_type       text        NOT NULL CHECK (subject_type IN ('action_request')),
  subject_id         uuid        NOT NULL,
  action_id          text        NOT NULL CHECK (length(action_id) <= 64),
  risk_class         text        NOT NULL CHECK (risk_class IN ('R1', 'R2', 'R3', 'R4')),
  action_digest      text        NOT NULL CHECK (action_digest ~ '^[0-9a-f]{64}$'),
  summary            text        NOT NULL CHECK (length(summary) BETWEEN 1 AND 500),
  requested_by       jsonb       NOT NULL,
  requester_user_id  uuid,
  required_approvals int         NOT NULL CHECK (required_approvals BETWEEN 1 AND 3),
  require_mfa        boolean     NOT NULL,
  approvals          int         NOT NULL DEFAULT 0 CHECK (approvals >= 0),
  status             text        NOT NULL DEFAULT 'pending'
                                 CHECK (status IN ('pending', 'approved', 'rejected', 'expired', 'consumed', 'cancelled')),
  expires_at         timestamptz NOT NULL,
  decided_at         timestamptz,
  consumed_at        timestamptz,
  created_at         timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, subject_type, subject_id),
  -- Critical actions: at least two people, each with a fresh second factor.
  CHECK (risk_class <> 'R4' OR (required_approvals >= 2 AND require_mfa)),
  CHECK (status <> 'consumed' OR consumed_at IS NOT NULL),
  CHECK (expires_at > created_at)
);
CREATE INDEX approval_requests_tenant_status_idx ON approval_requests (tenant_id, status, created_at DESC);

CREATE TABLE approval_decisions (
  tenant_id    uuid        NOT NULL,
  approval_id  uuid        NOT NULL,
  user_id      uuid        NOT NULL,
  decision     text        NOT NULL CHECK (decision IN ('approve', 'reject')),
  reason       text        CHECK (reason IS NULL OR length(reason) <= 500),
  mfa_verified boolean     NOT NULL,
  decided_at   timestamptz NOT NULL DEFAULT now(),
  -- One decision per person: the same person cannot count twice toward a quorum.
  PRIMARY KEY (tenant_id, approval_id, user_id),
  FOREIGN KEY (tenant_id, approval_id) REFERENCES approval_requests (tenant_id, id) ON DELETE CASCADE
);
CREATE TRIGGER approval_decisions_append_only
  BEFORE UPDATE OR DELETE ON approval_decisions
  FOR EACH ROW EXECUTE FUNCTION legion_append_only();
