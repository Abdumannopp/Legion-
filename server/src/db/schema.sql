-- Legion schema.
--
-- Applied idempotently on boot (see migrate.ts). Every statement must be safe
-- to re-run, because it executes on every start of every instance.

CREATE TABLE IF NOT EXISTS tenants (
  id                 uuid        PRIMARY KEY,
  name               text        NOT NULL,
  notification_email text,
  trial_ends_at      timestamptz,
  created_at         timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS users (
  id             uuid        PRIMARY KEY,
  email          text        NOT NULL,
  password_hash  text        NOT NULL,
  tenant_id      uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  role           text        NOT NULL CHECK (role IN ('admin', 'analyst', 'viewer')),
  status         text        NOT NULL DEFAULT 'active'
                             CHECK (status IN ('active', 'invited', 'disabled')),
  token_version  integer     NOT NULL DEFAULT 0,
  reset_token    text,
  reset_expires  timestamptz,
  invite_token   text,
  invite_expires timestamptz,
  invited_by     uuid,
  created_at     timestamptz NOT NULL DEFAULT now()
);

-- MFA. Added after the initial release, so these are ALTERs rather than columns
-- in the CREATE above — existing deployments must pick them up on boot.
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_secret text;
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_enabled boolean NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_enrolled_at timestamptz;

-- Email verification (hosted sign-up). Added later: the DEFAULT on the ADD
-- marks every account that already existed as verified (they were created
-- by invitation or first-run setup, which prove the address another way);
-- dropping it right after means new rows start unverified unless the code
-- says otherwise. Both statements are no-ops on the next boot.
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified_at timestamptz DEFAULT now();
ALTER TABLE users ALTER COLUMN email_verified_at DROP DEFAULT;
-- Only a SHA-256 of the emailed token is stored: a copy of the database is
-- not a set of working verification links.
ALTER TABLE users ADD COLUMN IF NOT EXISTS verify_token_hash text;
ALTER TABLE users ADD COLUMN IF NOT EXISTS verify_expires timestamptz;
CREATE UNIQUE INDEX IF NOT EXISTS users_verify_token_hash_idx ON users (verify_token_hash) WHERE verify_token_hash IS NOT NULL;

-- Recovery codes, one row per code, stored as bcrypt hashes. A used code is
-- marked rather than deleted so the user can see how many remain and the audit
-- trail records that one was spent.
CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
  id         uuid        PRIMARY KEY,
  user_id    uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash  text        NOT NULL,
  used_at    timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS mfa_recovery_user_idx ON mfa_recovery_codes (user_id)
  WHERE used_at IS NULL;

-- Replay protection. TOTP codes stay valid for a whole step (plus the window
-- either side), so a code observed in transit could otherwise be reused within
-- that period. One row per accepted counter value makes reuse impossible.
CREATE TABLE IF NOT EXISTS mfa_used_counters (
  user_id    uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  counter    bigint      NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, counter)
);

-- Email is the login identifier, so uniqueness is global and case-insensitive.
-- Enforcing it here rather than in application code is what makes concurrent
-- registration safe: two simultaneous requests can no longer both pass a
-- "does this email exist?" check and then both insert.
CREATE UNIQUE INDEX IF NOT EXISTS users_email_key ON users (lower(email));
CREATE INDEX IF NOT EXISTS users_tenant_idx ON users (tenant_id);
-- (Reset and invitation tokens are stored as hashes; see "Authentication
-- secrets at rest" at the end of this file.)

/**
 * Long-lived sessions.
 *
 * Access tokens are deliberately short (minutes) because they are stateless and
 * cannot be revoked; the refresh token is the revocable half and lives here.
 * Storing a hash, not the token, means a database leak does not hand over live
 * sessions.
 */
CREATE TABLE IF NOT EXISTS refresh_tokens (
  id          uuid        PRIMARY KEY,
  user_id     uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash  text        NOT NULL,
  -- Every token descended from one login shares a family id. If a stolen token
  -- is replayed after rotation, the whole family is revoked at once.
  family_id   uuid        NOT NULL,
  expires_at  timestamptz NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  -- Set when this token is exchanged. A second use of a rotated token is the
  -- signal that someone else has a copy.
  rotated_at  timestamptz,
  revoked_at  timestamptz,
  user_agent  text,
  ip_address  text
);

CREATE UNIQUE INDEX IF NOT EXISTS refresh_tokens_hash_idx ON refresh_tokens (token_hash);
CREATE INDEX IF NOT EXISTS refresh_tokens_user_idx ON refresh_tokens (user_id);
CREATE INDEX IF NOT EXISTS refresh_tokens_family_idx ON refresh_tokens (family_id);

CREATE TABLE IF NOT EXISTS alerts (
  tenant_id       uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  id              text        NOT NULL,
  title           text        NOT NULL,
  severity        text        NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
  agent           text        NOT NULL,
  status          text        NOT NULL DEFAULT 'open'
                              CHECK (status IN ('open', 'investigating', 'resolved')),
  summary         text        NOT NULL,
  confidence      real        NOT NULL DEFAULT 0,
  ai_explanation  text,
  explained_at    timestamptz,
  source_ip       text,
  target          text,
  mitre_technique text,
  source          text        NOT NULL DEFAULT 'manual',
  created_at      timestamptz NOT NULL DEFAULT now(),
  -- Composite key, not a global one. An alert ID supplied by one tenant must
  -- never collide with — or reveal the existence of — another tenant's alert.
  PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS alerts_tenant_created_idx ON alerts (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS alerts_tenant_status_idx ON alerts (tenant_id, status);
CREATE INDEX IF NOT EXISTS alerts_tenant_severity_idx ON alerts (tenant_id, severity);
-- Backs the trailing-window risk recalculation for a given asset.
CREATE INDEX IF NOT EXISTS alerts_tenant_target_idx ON alerts (tenant_id, target, created_at DESC)
  WHERE target IS NOT NULL;

CREATE TABLE IF NOT EXISTS assets (
  id          text        NOT NULL,
  tenant_id   uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name        text        NOT NULL,
  os          text        NOT NULL DEFAULT 'unknown',
  ip_address  text,
  risk        text        NOT NULL DEFAULT 'low'
                          CHECK (risk IN ('critical', 'high', 'medium', 'low')),
  online      boolean     NOT NULL DEFAULT true,
  last_seen   timestamptz NOT NULL DEFAULT now(),
  -- Hostname is the natural key the sensors report, and it is what makes the
  -- ingestion upsert possible without a read-then-write race.
  PRIMARY KEY (tenant_id, name)
);

CREATE INDEX IF NOT EXISTS assets_tenant_seen_idx ON assets (tenant_id, last_seen DESC);

CREATE TABLE IF NOT EXISTS audit_log (
  id            uuid        PRIMARY KEY,
  tenant_id     uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  user_id       uuid,
  user_email    text,
  action        text        NOT NULL,
  resource_type text,
  resource_id   text,
  detail        text,
  ip_address    text,
  created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS audit_tenant_created_idx ON audit_log (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS audit_tenant_action_idx ON audit_log (tenant_id, action);

CREATE TABLE IF NOT EXISTS subscriptions (
  tenant_id              uuid        PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
  status                 text        NOT NULL
                                     CHECK (status IN ('trialing', 'active', 'past_due', 'paused', 'canceled')),
  paddle_customer_id     text        NOT NULL DEFAULT '',
  paddle_subscription_id text,
  paddle_price_id        text,
  current_period_end     timestamptz,
  cancel_at_period_end   boolean     NOT NULL DEFAULT false,
  last_event_at          timestamptz
);

-- One Paddle subscription maps to exactly one tenant.
CREATE UNIQUE INDEX IF NOT EXISTS subscriptions_paddle_idx
  ON subscriptions (paddle_subscription_id)
  WHERE paddle_subscription_id IS NOT NULL;

-- One-time token that authorises creating the FIRST administrator on a
-- self-hosted install. At most one row. Only the SHA-256 is stored, so a copy
-- of the database (or a backup) cannot be used to claim a fresh install.
-- Printed to the server console at startup; deleted the moment it is used.
CREATE TABLE IF NOT EXISTS setup_token (
  id          smallint    PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  token_hash  text        NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);

-- Transactional outbox for notifications that must not be lost.
-- A row is written in the SAME transaction as the alert that needs it, so an
-- alert can never be stored without its notification also being stored. A
-- background worker delivers due rows, retrying with exponential backoff
-- until max_attempts, then marks the row 'dead' so it stays visible.
CREATE TABLE IF NOT EXISTS notification_outbox (
  id              uuid        PRIMARY KEY,
  tenant_id       uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  kind            text        NOT NULL CHECK (kind IN ('alert_email')),
  -- One notification per (tenant, kind, subject): enqueueing twice is a no-op.
  dedupe_key      text        NOT NULL,
  recipient       text        NOT NULL,
  payload         jsonb       NOT NULL,
  status          text        NOT NULL DEFAULT 'pending'
                              CHECK (status IN ('pending', 'sending', 'sent', 'dead')),
  attempts        integer     NOT NULL DEFAULT 0,
  max_attempts    integer     NOT NULL,
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  -- While 'sending', the claim expires at this time; a crashed worker's row
  -- becomes due again instead of being stuck forever.
  locked_until    timestamptz,
  last_error      text,
  created_at      timestamptz NOT NULL DEFAULT now(),
  sent_at         timestamptz
);

CREATE UNIQUE INDEX IF NOT EXISTS notification_outbox_dedupe
  ON notification_outbox (tenant_id, kind, dedupe_key);
CREATE INDEX IF NOT EXISTS notification_outbox_due
  ON notification_outbox (next_attempt_at) WHERE status IN ('pending', 'sending');
CREATE INDEX IF NOT EXISTS notification_outbox_tenant
  ON notification_outbox (tenant_id, created_at DESC);

-- Languages (en / ru / uz). notification_locale: the language of this
-- organisation's alert emails, chosen in Settings. ai_explanation_locale: the
-- language a stored AI explanation was written in, so a reader in another
-- language gets a fresh one instead of a foreign-language answer.
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS notification_locale text NOT NULL DEFAULT 'en';
ALTER TABLE tenants DROP CONSTRAINT IF EXISTS tenants_notification_locale_check;
ALTER TABLE tenants ADD CONSTRAINT tenants_notification_locale_check
  CHECK (notification_locale IN ('en', 'ru', 'uz'));
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS ai_explanation_locale text;

-- Durable realtime delivery. The dashboard's "new alert" frame used to be
-- published fire-and-forget after the alert committed: a Redis outage, or a
-- crash between commit and publish, meant other instances never pushed it.
-- It is now an outbox job of its own kind, written in the alert's
-- transaction and retried like an email. (The inline CHECK above is named
-- notification_outbox_kind_check by Postgres; replacing it is idempotent.)
ALTER TABLE notification_outbox DROP CONSTRAINT IF EXISTS notification_outbox_kind_check;
ALTER TABLE notification_outbox ADD CONSTRAINT notification_outbox_kind_check
  CHECK (kind IN ('alert_email', 'realtime_alert'));
-- Queue health metrics: oldest undelivered job and the dead-letter count,
-- without scanning delivered history.
CREATE INDEX IF NOT EXISTS notification_outbox_undelivered_age
  ON notification_outbox (created_at) WHERE status IN ('pending', 'sending');
CREATE INDEX IF NOT EXISTS notification_outbox_dead
  ON notification_outbox (tenant_id, created_at DESC) WHERE status = 'dead';

-- Sensor webhook credentials (Wazuh and anything speaking the same shape).
--
-- One row per credential; a tenant may hold several at once, which is what
-- makes rotation with an overlap possible. Nothing here is derived from a
-- server-wide secret: the secret is 256 random bits generated per credential.
--
--   key_id      Public identifier sent with every request. It is how the
--               server learns WHICH tenant a request claims to belong to —
--               from the credential, never from a header the sender chooses.
--               Not a secret; its only power is to select a row.
--   secret_enc  The HMAC key, AES-256-GCM encrypted (webhook-auth.ts) under a
--               key that lives in the server's environment, not in this
--               database — a copy of the database or a backup does not hand
--               over working credentials. The signature scheme needs the
--               server to know the secret, so it cannot be a one-way hash.
--   expires_at  Set when the credential is rotated: the old one keeps working
--               until then, so the sender can be reconfigured without an outage.
--   revoked_at  Immediate kill switch. Checked on every request, no caching.
CREATE TABLE IF NOT EXISTS webhook_credentials (
  key_id       text        PRIMARY KEY,
  tenant_id    uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  secret_enc   text        NOT NULL,
  label        text        NOT NULL DEFAULT '',
  created_at   timestamptz NOT NULL DEFAULT now(),
  created_by   uuid,
  expires_at   timestamptz,
  revoked_at   timestamptz,
  last_used_at timestamptz,
  rotated_from text
);
CREATE INDEX IF NOT EXISTS webhook_credentials_tenant_idx
  ON webhook_credentials (tenant_id, created_at DESC);

-- Replay protection: every accepted request's nonce is recorded, per
-- credential, until its timestamp can no longer pass the freshness check.
-- The primary key makes "have I seen this?" and "remember it" one atomic
-- statement, so two instances cannot both accept the same request.
CREATE TABLE IF NOT EXISTS webhook_nonces (
  key_id     text        NOT NULL REFERENCES webhook_credentials(key_id) ON DELETE CASCADE,
  nonce      text        NOT NULL,
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (key_id, nonce)
);
CREATE INDEX IF NOT EXISTS webhook_nonces_expiry_idx ON webhook_nonces (expires_at);

-- Per-organisation AI control. ai_enabled NULL = "never chosen": the
-- deployment default applies (config.aiTenantDefault). ai_data_mode 'strict'
-- replaces IP addresses, e-mail addresses and hostnames with reversible
-- placeholders before anything is sent to the provider.
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS ai_enabled boolean;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS ai_data_mode text NOT NULL DEFAULT 'standard';
ALTER TABLE tenants DROP CONSTRAINT IF EXISTS tenants_ai_data_mode_check;
ALTER TABLE tenants ADD CONSTRAINT tenants_ai_data_mode_check CHECK (ai_data_mode IN ('standard', 'strict'));
-- Provenance of a stored explanation: written by a model ('ai') or by
-- Legion's deterministic fallback ('local'). NULL = from before this existed.
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS ai_explanation_source text;
ALTER TABLE alerts DROP CONSTRAINT IF EXISTS alerts_ai_explanation_source_check;
ALTER TABLE alerts ADD CONSTRAINT alerts_ai_explanation_source_check CHECK (ai_explanation_source IN ('ai', 'local'));

-- Alert change cursor (realtime reliability).
--
-- PostgreSQL is the source of truth; WebSocket/Redis frames are only hints that
-- something changed. A client that missed frames (Redis down, socket dropped,
-- server restarted, tab in the background) recovers by asking Postgres for
-- "everything after the last change I have", which needs a cursor that cannot
-- skip rows.
--
--   seq          Per-tenant version of the row: bumped on EVERY insert and
--                update (a status change or an explanation is a change too).
--   created_seq  The seq the row was created with. A change with
--                created_seq > a client's baseline is an alert that client has
--                never seen; otherwise it is an update to one it has.
--   tenants.alert_seq  The tenant's latest seq (the cursor).
--
-- Why a counter on the tenant row and not a sequence: a sequence hands out
-- numbers in the order transactions START, but they become visible in the
-- order they COMMIT. A client that had seen seq 101 would then never fetch 100
-- if 100 committed second. Incrementing a counter on the tenant row takes that
-- row's lock until commit, so numbers are handed out — and become visible — in
-- the same order, with no gaps (a rolled-back insert rolls its number back).
-- The cost is that one tenant's alert writes commit one at a time.
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS alert_seq bigint NOT NULL DEFAULT 0;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS seq bigint;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS created_seq bigint;

CREATE OR REPLACE FUNCTION alerts_assign_seq() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.seq IS NULL THEN
      UPDATE tenants SET alert_seq = alert_seq + 1 WHERE id = NEW.tenant_id RETURNING alert_seq INTO NEW.seq;
    END IF;
    NEW.created_seq := COALESCE(NEW.created_seq, NEW.seq);
  -- An UPDATE that sets seq itself (the one-time backfill below) is left alone.
  ELSIF NEW.seq IS NOT DISTINCT FROM OLD.seq THEN
    UPDATE tenants SET alert_seq = alert_seq + 1 WHERE id = NEW.tenant_id RETURNING alert_seq INTO NEW.seq;
  END IF;
  RETURN NEW;
END
$$;

CREATE OR REPLACE TRIGGER alerts_assign_seq_trg
  BEFORE INSERT OR UPDATE ON alerts
  FOR EACH ROW EXECUTE FUNCTION alerts_assign_seq();

-- Existing rows (a database from before this existed): number them in creation
-- order, after whatever the counter already holds. Runs only while some row has
-- no seq, and the migration lock means one instance does it.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM alerts WHERE seq IS NULL) THEN
    UPDATE alerts a SET seq = n.value, created_seq = n.value
      FROM (
        SELECT x.tenant_id, x.id, t.alert_seq + row_number() OVER (PARTITION BY x.tenant_id ORDER BY x.created_at, x.id) AS value
          FROM alerts x JOIN tenants t ON t.id = x.tenant_id
         WHERE x.seq IS NULL
      ) n
     WHERE a.tenant_id = n.tenant_id AND a.id = n.id;
    UPDATE tenants t SET alert_seq = m.top
      FROM (SELECT tenant_id, max(seq) AS top FROM alerts GROUP BY tenant_id) m
     WHERE m.tenant_id = t.id AND m.top > t.alert_seq;
  END IF;
END
$$;

ALTER TABLE alerts ALTER COLUMN seq SET NOT NULL;
ALTER TABLE alerts ALTER COLUMN created_seq SET NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS alerts_tenant_seq_idx ON alerts (tenant_id, seq);
-- The dashboard's list order (newest first, arrival order among equals).
CREATE INDEX IF NOT EXISTS alerts_tenant_created_seq_idx ON alerts (tenant_id, created_at DESC, seq DESC);

-- Authentication secrets at rest.
--
-- Reset and invitation tokens were stored in plaintext, so a copy of the
-- database (or a backup, or a read-only SQL injection) was a set of working
-- account-takeover and account-claim links. They are now stored as SHA-256
-- hashes — the tokens are 256 random bits, so a fast hash is enough — and
-- looked up by hash. The same scheme verify_token_hash already used.
--
-- TOTP seeds cannot be hashed (the server recomputes codes from them), so they
-- are encrypted with AES-256-GCM under LEGION_ENCRYPTION_KEYS
-- (secret-box.ts). That needs the key, which SQL does not have: the conversion
-- of existing plaintext seeds runs in the application at boot
-- (secrets-migration.ts), and until then a plaintext seed keeps working.
ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token_hash text;
ALTER TABLE users ADD COLUMN IF NOT EXISTS invite_token_hash text;
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_secret_enc text;

-- Existing live links keep working: hashing the stored token gives exactly the
-- hash of the token in the e-mail. Idempotent — after the first run there is
-- nothing left to convert.
UPDATE users SET reset_token_hash = encode(sha256(convert_to(reset_token, 'UTF8')), 'hex'), reset_token = NULL
 WHERE reset_token IS NOT NULL;
UPDATE users SET invite_token_hash = encode(sha256(convert_to(invite_token, 'UTF8')), 'hex'), invite_token = NULL
 WHERE invite_token IS NOT NULL;

-- The old plaintext columns stay (so an older instance still running during a
-- rolling upgrade gets an error rather than a missing column), but nothing may
-- ever be written to them again. An older instance's reset or invite therefore
-- FAILS during the rollout instead of storing a plaintext token.
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_no_plaintext_tokens;
ALTER TABLE users ADD CONSTRAINT users_no_plaintext_tokens CHECK (reset_token IS NULL AND invite_token IS NULL);

DROP INDEX IF EXISTS users_invite_token_idx;
DROP INDEX IF EXISTS users_reset_token_idx;
CREATE UNIQUE INDEX IF NOT EXISTS users_reset_token_hash_idx ON users (reset_token_hash) WHERE reset_token_hash IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS users_invite_token_hash_idx ON users (invite_token_hash) WHERE invite_token_hash IS NOT NULL;

-- Notification address confirmation. An administrator's NEW address waits in
-- notification_email_pending until its owner confirms it by link; only then does
-- it become notification_email, the address alert emails go to. Without this, any
-- (hosted) tenant could make the platform send its alert text to any inbox.
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS notification_email_pending text;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS notification_email_token_hash text;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS notification_email_token_expires timestamptz;
CREATE UNIQUE INDEX IF NOT EXISTS tenants_notification_token_hash_idx ON tenants (notification_email_token_hash) WHERE notification_email_token_hash IS NOT NULL;
CREATE INDEX IF NOT EXISTS notification_outbox_tenant_kind_created_idx ON notification_outbox (tenant_id, kind, created_at);
CREATE INDEX IF NOT EXISTS audit_log_tenant_action_created_idx ON audit_log (tenant_id, action, created_at);
