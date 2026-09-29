# Legion — Security Hardening (2026-09-29)

This is phase 2 of the production-readiness audit (`PRODUCTION-READINESS-AUDIT-2026-09-29.md`). Every change
below has a regression test. No existing security control was relaxed, and no test was disabled or weakened to
pass. Where an existing test had to change, the reason is listed under "Existing tests that changed".

**Branch:** `claude/laughing-clarke-cmfudk`. Commit `bcbe9b5` imports the delivered source unchanged (audit P0-1);
each later commit is one hardening area.

---

## 1. What was already in place (verified, kept, re-tested)

The audit found several requested controls already implemented correctly. They were **not** rewritten; their
existing tests were re-run:

| Requirement | Where | Existing evidence |
|---|---|---|
| Per-tenant random webhook secret (no deterministic/global derivation) | `webhook-credentials.ts`, `webhook-auth.ts` | `webhook-auth.test.ts` → "credentials are random and unique", "the old derived key signs nothing" |
| HMAC-SHA256 over `v2.<timestamp>.<nonce>.<raw body>` | `webhook-auth.ts` | "a forged signature…", "a modified body…" |
| Constant-time comparison (unknown key costs the same) | `webhook-credentials.ts` | `webhook-constant-time.test.ts` |
| Replay protection + timestamp tolerance | `webhook_nonces`, `WEBHOOK_MAX_SKEW_SECONDS` | "replay…", "the time window…" |
| Rotation with overlap, immediate revocation, revoke-all | `webhook-credentials.ts` | "rotation…", "revocation…" |
| Secrets encrypted at rest; never logged or echoed | `secret-box.ts` | "secrets stay secret…", `secrets-at-rest.test.ts` |
| Reset / invite / verify / setup tokens stored as SHA-256, consumed atomically | `auth-tokens.ts`, `store.ts` | `api.test.ts`, `first-admin.test.ts` |
| Refresh tokens hashed, rotated, family revocation on reuse | `sessions.ts` | `sessions.test.ts` |
| TOTP seeds under AES-256-GCM with a versioned keyring (`kid` in ciphertext), record-bound AAD, rotation migration | `secret-box.ts`, `mfa.ts`, `secrets-migration.ts` | `mfa.test.ts`, `secrets-at-rest.test.ts` |
| Tenant isolation, IDOR/BOLA, cross-workspace access, WebSocket and AI-context isolation, background jobs | all stores | `cross-tenant-attacks.test.ts`, `tenant-isolation-sweep.test.ts` (with a route-coverage check) |
| CORS exact allow-list, WebSocket Origin check, explicit proxy trust | `edge.ts`, `edge-parse.ts` | `edge-http.test.ts`, `edge-proxy.test.ts` |

---

## 2. Changes

### 2.1 Webhook ingestion

| Change | Why | Files |
|---|---|---|
| The body is received as raw bytes (`express.raw`, JSON types only), and the HMAC is verified **before** `JSON.parse` | An unauthenticated sender's body is never parsed | `server/src/index.ts` |
| `webhookFailureGate`: failed authentications (400/401/413/415) counted per client address; over `WEBHOOK_FAILED_AUTH_PER_MINUTE` (60) → 429 before the body is read or the DB is touched. Signed deliveries never count. | Audit P1-3: the unauthenticated webhook path was exempt from all limits | `server/src/webhook-guard.ts`, `bounded-counter.ts` |
| `WEBHOOK_MAX_BODY_BYTES` (1 MB) for this route | Large Wazuh events were dropped at 256 KB | `server/src/config.ts` |
| The integration script trims only the tail of an oversized `full_log` | A 413 used to drop the event for good | `integrations/custom-legion.py` |

### 2.2 Authentication

| Change | Why | Files |
|---|---|---|
| Unknown or invited accounts compared against a **real** cost-12 dummy hash | Audit P1-14: the old 64-character placeholder answered in ~1 ms vs ~300 ms (user enumeration) | `server/src/account-security.ts` |
| Failed logins audited (`auth.login_failed`) | Guessing becomes visible to administrators | `index.ts` |
| **Suspicious sign-in detection**: a device the account never used (UA without version numbers), or success after ≥5 failures in 15 min → `auth.login_suspicious` audit + email to the owner | Requested | `account-security.ts`, table `user_known_devices` |
| Turning MFA on or off revokes every **other** session (token_version + refresh families) and starts a fresh one for this browser | An attacker's pre-MFA session survived enabling MFA | `index.ts` |
| Owner notices (en/ru/uz, no action links) for password change or reset, MFA on/off, recovery-code regeneration | Unexpected security changes are noticed | `mailer.ts` |
| Step-up endpoints (change-password, MFA enable/disable, recovery codes): `authLimiter` + a per-user failure limiter shared across instances | A stolen session could guess the password at 300/min from rotating IPs | `ratelimit.ts` |
| forgot-password / resend-verification: per-address cap (`MAIL_PER_ADDRESS_HOURLY`); SMTP no longer awaited | Mail-bombing; SMTP latency revealed which addresses exist | `index.ts`, `ratelimit.ts` |

### 2.3 Tokens and sessions

| Change | Why | Files |
|---|---|---|
| Access, MFA-challenge and checkout tokens each use their own HKDF-derived key and audience, with `iss`/`aud`/`typ`/`kid` required | Purposes were separated only by a claim check; now a token of one kind does not verify as another | `server/src/auth-jwt.ts` |
| `JWT_PREVIOUS_SECRETS`: verification-only old secrets; weak values refused at boot | The signing key can be rotated without signing everyone out | `auth-jwt.ts`, `config.ts` |
| Checkout-token binding bounded to 8 days (expiry was ignored outright); legacy tokens honoured within the same bound | Audit P2-11 | `index.ts` |
| `SESSION_ABSOLUTE_DAYS` (30): a login's hard maximum life | Audit P2-2: rotation extended sessions forever | `sessions.ts` |
| Dashboard refresh serialised across tabs (Web Locks) and skipped if another tab just refreshed | Audit P1-8: tabs racing triggered reuse detection and logged the user out | `frontend/lib/session-refresh.ts`, `api.ts` |
| Server reuse detection stays **strict by default**. `REFRESH_REUSE_GRACE_SECONDS` exists as a documented opt-in (once, same browser, ≤60 s). | Enabling a grace window by default would let a replay with a copied user agent go unnoticed | `sessions.ts`, `config.ts` |

### 2.4 Authorization

| Change | Why | Files |
|---|---|---|
| `subscriptionGate` over every agent-layer prefix; actions that **stop** agents (kill switch, suspend, revoke, removals) always allowed | Audit P1-6: blocked tenants kept creating agents and running paid AI skills | `server/src/agents.ts` |
| Demote/deactivate check "keeps an admin" and apply the change in one transaction holding row locks | Audit P2-4: mutual demotion could leave zero admins | `store.ts`, `index.ts` |
| List query strings validated with zod; `offset` ≤ 10 000; `/assets` capped; non-UUID ids → 404 | Audit P2-5: `limit=abc` → `LIMIT NaN` → 500 | `index.ts`, `store.ts` |

### 2.5 Network and browser

| Change | Why | Files |
|---|---|---|
| Dashboard CSP: per-request nonce + `'strict-dynamic'`, `script-src-attr 'none'`; no `'unsafe-inline'` scripts | Any HTML injection used to execute | `frontend/proxy.ts`, `lib/csp.ts`, `next.config.mjs` |
| CSRF: `Sec-Fetch-Site: cross-site` refused on state changes (signed machine endpoints exempt) | Covers browsers that omit `Origin` | `server/src/edge.ts` |
| HSTS whenever HTTPS + secure cookies (not only `NODE_ENV=production`); nginx sends it too | Self-hosted installs never sent HSTS | `edge.ts`, `deploy/nginx.conf` |
| nginx: `limit_req` for `/api/auth/` and `/api/` (not the webhook), 2 MB body cap, header/body timeouts, real-IP guidance | Floods stopped before Node | `deploy/nginx.conf` |
| `/health`: the public sees `{status, database}` only; details for loopback operators or `HEALTH_METRICS_TOKEN`; DB probe ≤1/s | Version and AI vendor were public; probe was unthrottled | `index.ts` |
| WebSocket: per-user (20) and per-tenant (1000) caps, ping/pong liveness (30 s), >1 MB unsent → disconnect | Unbounded sockets, dead connections and slow-reader memory | `realtime.ts`, `index.ts` |
| Malformed settings refuse to boot: `DEPLOYMENT_MODE` typos, non-integer or out-of-range numbers, bad severity, non-https `PADDLE_API_BASE` | A typo silently enabled open sign-up on a self-hosted install | `config.ts` |
| SSRF / outbound: Paddle client `redirect:"error"`, 15 s timeout, fixed error text to tenants; source check that every server `fetch()` refuses redirects; outbound hosts come from configuration only | The API key could follow a redirect; transport details reached tenants | `paddle.ts` |

### 2.6 Schema migrations (all additive, idempotent, no rewrites)

```sql
CREATE TABLE IF NOT EXISTS user_known_devices (...);                               -- new table
CREATE INDEX IF NOT EXISTS audit_log_tenant_action_user_created_idx ON audit_log (...);
ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS family_started_at timestamptz;  -- nullable, no default
ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS grace_used_at timestamptz;      -- nullable, no default
```

Nullable columns without defaults are metadata-only in PostgreSQL. Existing refresh rows use their own
`created_at` as the start of the absolute lifetime. On a large production `audit_log`, create the new index
beforehand with `CREATE INDEX CONCURRENTLY` (same name), so the boot-time statement is a no-op.

### 2.7 Backward compatibility

- **Access tokens issued before the upgrade** (≤15 min old) are refused once. The dashboard renews them from the
  refresh cookie transparently. API clients using bearer tokens sign in again.
- **Checkout tokens issued before the upgrade** still attribute payments (within 8 days).
- **`/health` from the server itself** returns the same detail as before. Through a proxy it returns less (see
  INSTALL.md).
- **Webhook responses.** Correctly signed requests behave as before. Unsigned malformed JSON is now 401 (was 400).
  Events up to 1 MB are accepted (was 256 KB).
- **Config.** A server whose `.env` has a malformed value now refuses to start and names the setting.

### 2.8 Existing tests that changed (and why)

| File | Change | Reason |
|---|---|---|
| 18 test files | `jwt.sign(…, config.jwtSecret)` → `mint(…)` (`tests/helpers/tokens.ts`) | Tokens must be minted exactly as the server does. Deliberate forgeries (wrong secret) are kept as forgeries. |
| `webhook-auth.test.ts` | "broken JSON is 400" split into unsigned → 401 and signed → 400; oversize threshold uses the new limit | Stricter behaviour; both cases asserted |
| `edge-http.test.ts` | MFA-enable setup step uses its own address; reloads the user after enabling | `/auth/mfa/enable` is now rate-limited and rotates sessions |
| `backup-scripts.test.ts` | Swap the DB user via the URL API | Pre-existing test bug: the string replace missed URLs with a password, so a "must fail" backup ran as superuser |

---

## 3. Evidence

### 3.1 Test runs (this commit, real PostgreSQL 16)

See section 3.3. The raw logs are summarised there.

### 3.2 Fixes proven by failing first

Where practical, a fix was reverted locally to show that its test fails without it:

| Test | Without the fix | With the fix |
|---|---|---|
| Login timing (`auth-hardening.test.ts`) — old 64-char dummy hash restored | 2 failed | pass |
| Subscription gate (`authorization-hardening.test.ts`) — gate unmounted | 2 failed | pass |
| Multi-tab refresh (`frontend/lib/session-refresh.test.ts`) — no coordination | the first test reproduces the logout | lock variant passes |

### 3.3 Browser check of the CSP (production build, Chromium 1194)

- Every server-rendered `<script>` on `/`, `/login`, `/signup`, `/privacy` and `/forgot-password` carried the
  response's nonce. Pages hydrated. No CSP violations were reported.
- An inline `<script>` and an `onerror=` handler injected into the served HTML were both **refused** by the
  browser.
- `deploy/nginx.conf` passed `nginx -t`. The only error was the sandbox's missing IPv6 socket for
  `listen [::]:80`.

---

## 4. Known issues found, not changed here

- **Agent-identity lockfile out of sync (pre-existing).** `packages/agent-identity/package-lock.json` lacks
  `libpg-query` / `@pgsql/types`, so `npm ci` there fails, and so does the CI job that runs it. Regenerate with
  `npm install` in that folder and commit the lockfile.
- **Invitation hourly cap is check-then-act.** A burst of concurrent invites can exceed it slightly. This is
  low-risk (bounded, audited) and can be fixed with the same row-lock pattern.
- **The CSP keeps `style-src 'unsafe-inline'`.** React `style={}` attributes need it. Scripts, the
  XSS-relevant part, are nonce-only.
- **Items outside this phase** remain in the audit roadmap: RLS, versioned migrations, ingestion durability,
  billing price allow-list, retention and deletion.
