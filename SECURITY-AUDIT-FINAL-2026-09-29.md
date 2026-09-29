# Legion — final security audit (2026-09-29)

Scope: the whole repository — the API (`server/`), dashboard (`frontend/`),
agent layer (`packages/agent-identity/`), Wazuh integration (`integrations/`),
operations and backup scripts (`ops/`) and deployment files (`deploy/`).

Method: a read-only review in four parallel streams:
1. identity: authentication, sessions, JWT, MFA, password reset, invitations
2. ingestion and edge: the Wazuh webhook, the outbox, Redis, the WebSocket, billing, CORS/CSP, rate limiting, files
3. AI, secrets, database, logging, backups, deployment, frontend and dependencies
4. the agent layer

Each Critical and High candidate was then re-verified against the code, and
probed where cheap, before anything was changed. Only the Critical and High
issues were fixed in this pass.

Passing tests do not make Legion secure. The tests prove the specific
properties listed under each fix. They do not prove the absence of other
flaws. See "Recommended penetration-test scope".

---

## Fixed in this pass

### C-1 CRITICAL — A published signing key was accepted, so anyone could forge sessions (FIXED)

- **Affected:** `server/.env.example`, `server/src/config.ts` (placeholder check), `server/scripts/setup.mjs`, `server/src/seed.ts`.
- **Problem:** `.env.example` shipped `JWT_SECRET=replace-with-a-long-random-string`. That is 33 characters with no `local-` prefix, so the placeholder check (`startsWith("local-") || length < 32`) accepted it even with `NODE_ENV=production`. The same file set `NODE_ENV=development`, which switched off both the JWT placeholder check and the encryption-keyring check. It also set `SEED_DEMO_DATA=true`, which creates `admin@legion.demo / legion123`. `setup.mjs` kept an existing `JWT_SECRET`, so running setup over a copied example preserved the published key. Hosted (SaaS) mode seeded the demo admin by default whenever NODE_ENV was unset.
- **Attack scenario:** An operator runs `cp server/.env.example server/.env` and then `npm start`, or `npm run setup`, or `start-legion.ps1` (which skips setup when `.env` exists). An unauthenticated attacker then either:
  - signs an HS256 token with the published secret for any user and tenant id they have seen. That bypasses the password and MFA and gives the victim's role, including admin; or
  - logs in as the demo admin.
- **Business impact:** Full takeover of every tenant on that installation. MFA seeds are sealed under a key derived from the same public secret when no keyring is set, so a later database or backup leak exposes them too.
- **Fix:**
  - `isWeakJwtSecret()` rejects template phrases, `local-*` values, anything shorter than 32 characters and anything with fewer than 10 distinct characters. It applies in every mode except `NODE_ENV=test`.
  - Development may use a weak secret only while the API is bound to loopback, and never a value copied from a template.
  - The keyring requirement gets the same loopback rule.
  - `.env.example` now ships an empty `JWT_SECRET` and no active `NODE_ENV` or `SEED_DEMO_DATA`.
  - `setup.mjs` replaces a weak or template secret and warns about `NODE_ENV=development`.
  - Demo seeding is opt-in in every mode, never runs in production, and is refused unless the API listens on loopback.
- **Tests:** `server/tests/secret-placeholders.test.ts` (12 cases):
  - the shipped value is refused with NODE_ENV unset, `production` or `development`
  - a development default on a non-loopback bind is refused
  - random secrets boot
  - the weak-secret classifier
  - hosted mode no longer seeds by default
  - `.env.example` contents
  - setup's regeneration rule

### H-1 HIGH — A live-alert WebSocket outlived the session that opened it (FIXED)

- **Affected:** `server/src/index.ts` (WebSocket upgrade, `/auth/logout`), `server/src/realtime.ts`, `frontend/lib/realtime/alert-sync.ts`.
- **Problem:** The socket was authorized once, at the handshake. Revalidation checked user status, tenant and token version, but never the token's expiry. Logout did not close sockets.
- **Attack scenario:** An attacker obtains a 15-minute access token, for example from a shared machine or through a browser extension. From a script with an allowed `Origin` header they open `/ws/alerts`. They then receive every new alert of the tenant indefinitely, surviving token expiry and the victim's logout.
- **Business impact:** A continuous, silent leak of the customer's security telemetry, from a credential that was only valid for minutes.
- **Fix:**
  - Each socket's grant records the access token's `exp` and a SHA-256 of the token.
  - A per-socket timer closes the socket at expiry with code 4401. Periodic revalidation also closes expired grants.
  - `/auth/logout` closes the sockets opened with that browser's token.
  - The dashboard handles 4401 by syncing over HTTP first. That request refreshes the session, so legitimate users reconnect seamlessly.
- **Tests:**
  - `server/tests/ws-session-lifetime.test.ts` (5 cases): expiry closes the socket, revalidation closes expired grants, logout closes only that token's sockets, an expired token is refused, and a refreshed session reconnects.
  - `frontend/lib/realtime/alert-sync.test.ts` (+2 cases): 4401 triggers an immediate sync; an ordinary drop does not.

### H-2 HIGH — The platform's mail server could be used as an open, attacker-written mail relay (hosted mode) (FIXED)

- **Affected:** `server/src/index.ts` (`/notifications/settings`, `/notifications/test`, `/users/invite`), `server/src/outbox.ts`, `server/src/store.ts`, `server/src/db/schema.sql`, `server/src/mailer.ts`.
- **Problem:**
  - Any administrator could set `notification_email` to any address, with no confirmation from its owner.
  - Alert email subjects and bodies are sensor-controlled (alert title and summary).
  - The webhook is exempt from rate limiting and from the subscription gate.
  - `/notifications/test` had only the per-IP API limit, and returned raw SMTP errors (host, account) to tenant administrators.
- **Attack scenario:** In hosted mode an attacker:
  1. Signs up and becomes admin of their own tenant.
  2. Sets `notification_email` to the victim's address and creates a sensor credential.
  3. Posts unlimited signed "critical" events carrying phishing text.

  Legion then emails the victim from the vendor's own SPF/DKIM-aligned domain.
- **Business impact:** Phishing under the vendor's brand. The shared mail domain or ESP account gets blocklisted, which breaks password reset, verification and invitations for every customer. It also means unbounded cost.
- **Fix:**
  - A new address goes into `notification_email_pending`. Its owner receives a confirmation email that says, in their language, "ignore this if you didn't expect it". The address becomes active only after the owner confirms on a dashboard page with an explicit button, so a mail scanner that opens links cannot confirm it.
  - The confirmation token is a hashed, single-use, 48-hour, one-time token.
  - While a change is pending, the old confirmed address keeps receiving alerts. Existing configured addresses keep working, so production alerting is not interrupted.
  - Per-tenant hourly caps, counted in the database so they hold across instances:
    - alert emails: `ALERT_EMAIL_HOURLY_CAP`, default 100 (alerts beyond the cap are still stored and shown)
    - confirmation emails: 5
    - test emails: 5
    - invitations: `INVITE_HOURLY_CAP`, default 50
  - SMTP error details go only to the sanitised server log.
- **Tests:** `server/tests/notification-confirmation.test.ts` (10 cases):
  - nothing is sent to an unconfirmed address
  - confirming activates the address and the token is single-use
  - the old address keeps receiving alerts while a change is pending
  - expired or forged tokens are refused, and the token is stored hashed
  - clearing the address is immediate
  - each of the four caps
  - SMTP detail never reaches the tenant administrator
- **Also updated:** `cross-tenant-attacks.test.ts` and `i18n.test.ts` for the new semantics.

### H-3 HIGH — Catastrophic regex backtracking froze the whole API (FIXED)

- **Affected:** `packages/agent-identity/src/prompt-guard/detectors.ts`.
- **Problem:** Several detectors were quadratic:
  - `markers.role_label` and `markers.fake_section` used `(?:^|\n)\s*…`.
  - `html.hidden_style` and `html.hidden_attr` had unbounded tag interiors.
  - `html.comment_text` found comments with a lazy `<!--[\s\S]*?-->`.
  - The markdown-image, `<img>` and `{{…}}` patterns were unbounded.

  Measured: 20,000 characters of repeated `<span hidden` took 7.7 s; 40,000 newlines took 3.8 s. The route accepts 200,000 characters, which extrapolates to minutes per request.
- **Attack scenario:** Any tenant's AI agent (no permissions needed) posts filler text to `/agent/v1/content/inspect`. Or a web page or API that an agent fetches returns such filler, because tool outputs are classified. Or a sensor writes it into alert text that a skill reads. Node's single event loop blocks.
- **Business impact:** The API stops responding for every tenant (login, ingestion, dashboards) for as long as the attacker keeps sending.
- **Fix:**
  - Line-anchored `/m` patterns.
  - Bounded tag and bracket interiors (`[^<>]{0,300}`, `{0,500}`, `{0,200}`).
  - Linear `indexOf` comment extraction.

  Measured after the fix: every one of 23 adversarial shapes at 200,000 characters takes 90 ms or less.
- **Tests:** `packages/agent-identity/test/prompt-guard.test.ts` (+11 cases). Ten adversarial shapes at 200k characters must each classify in under 1 s, and each bounded pattern must still detect its target. Against the old code this run did not finish within 2 minutes. All 170 prompt-guard and injection tests pass.

---

## Remaining findings (not fixed in this pass)

Format: **SEVERITY — affected — problem — attack — impact — fix — test.**

### MEDIUM

- **M-1 — Account enumeration through login timing**
  - Affected: `server/src/index.ts` (login dummy hash); `/auth/register`, `/users/invite` messages; forgot-password/resend-verification.
  - Problem: the dummy hash `"$2a$12$invalid…"` is not a valid bcrypt hash. `compare` returns in about 1 ms, against about 320 ms for real accounts.
    - Forgot-password and resend-verification await SMTP only for existing accounts.
    - Register and invite say "already registered / in use".
  - Attack: measure login response times, or read the registration message, to confirm which staff addresses have accounts.
  - Impact: targeted phishing and credential stuffing.
  - Fix:
    - Use a real precomputed cost-12 hash of random data.
    - Queue email through the outbox so request timing is the same either way.
    - Give uniform responses.
  - Test: median login time for unknown vs known email (wrong password) within 20%; `bcrypt.getRounds(DUMMY) === 12`.
- **M-2 — Refresh rotation vs. revoke-all race (suspected, not reproduced)**
  - Affected: `server/src/sessions.ts` (rotate / revokeAllForUser).
  - Problem: a rotation that straddles a concurrent `revokeAllForUser` inserts a new row the revocation does not see, under READ COMMITTED.
  - Attack: the holder of a stolen refresh token loops `/auth/refresh` while the victim resets the password.
  - Impact: a stolen session survives the standard remedy.
  - Fix: store the user's `token_version` (or `sessions_valid_after`) on each refresh row and reject on mismatch; or lock the user row in both paths.
  - Test: run a rotate and a revoke-all concurrently on two connections; the new token must be rejected.
- **M-3 — No absolute session lifetime; enabling or disabling MFA does not end other sessions**
  - Affected: `server/src/sessions.ts` (expiry reset on every rotation); `/auth/mfa/enable`, `/auth/mfa/disable`.
  - Attack: a thief refreshes forever, and the victim's switch to MFA does not evict them.
  - Fix: set an absolute family expiry at login; revoke other families on MFA change.
  - Test: a family past its absolute lifetime is refused; enabling MFA revokes other families.
- **M-4 — MFA enrolment without re-authentication; no admin or operator MFA reset**
  - Affected: `/auth/mfa/setup`, `/auth/mfa/enable`; `server/src/mfa.ts`.
  - Attack: someone with a hijacked session enrols their own authenticator, locking the victim out permanently (possibly the last admin).
  - Fix: require the password to enable MFA; add an audited admin reset (bumping `token_version`) and an operator CLI.
  - Test: enabling without a password returns 400; an admin reset clears MFA and revokes sessions.
- **M-5 — Password alone regenerates recovery codes, which then disable MFA; no per-account limiter on re-auth endpoints**
  - Affected: `/auth/mfa/recovery-codes`, `/auth/mfa/disable`, `/auth/change-password`.
  - Attack: with a hijacked session, brute-force the password via change-password (300/min per IP), regenerate the codes, then disable MFA.
  - Fix: require a TOTP code or an existing recovery code to regenerate; apply per-user failure limiters.
  - Test: regenerating with only a password returns 400; the sixth wrong password in 15 minutes returns 429.
- **M-6 — Paddle checkout token never expires and can rebind a tenant's subscription**
  - Affected: `server/src/index.ts` (`ignoreExpiration: true`); `server/src/store.ts` (one row per tenant).
  - Attack: a former admin (or anyone who captured the token) opens a new checkout later. A later cancel sets the whole tenant to `canceled` (402). The billing portal then opens the attacker's Paddle customer. Also, an older subscription's events can overwrite a newer one.
  - Fix: single-use, DB-backed checkout nonce with 24–72 h validity; never rebind a tenant with an active different subscription; key state by subscription id.
  - Test: an old token plus a new subscription id does not change an active tenant's row; A-active, B-active, A-cancel leaves access `ok`.
- **M-7 — Hosted pre-account hijacking and email squatting**
  - Affected: `/auth/register`, email verification.
  - Attack:
    1. The attacker registers `cfo@victim.com` with their own password.
    2. The victim clicks "confirm".
    3. The attacker logs in and waits for the victim's data.

    Also, squatted addresses block legitimate invites.
  - Fix: set the password at verification (or require it); expire unverified accounts; let a new registration replace an unverified one.
  - Test: an unverified account older than 24 h does not block register or invite.
- **M-8 — Redis has no authentication or TLS requirement, and pub/sub envelopes are unauthenticated**
  - Affected: `server/src/realtime.ts` (subscriber trusts `envelope.tenant_id`), `server/src/ratelimit.ts`, `server/src/config.ts`.
  - Attack: anyone on the Redis network can:
    - `SUBSCRIBE` to read every tenant's new alerts
    - `PUBLISH` forged frames to any tenant
    - delete rate-limit keys to reset brute-force counters
  - Fix: refuse production boot without `rediss://` or a password; HMAC-sign envelopes with a keyring-derived key; optionally publish only ids.
  - Test: an unsigned envelope is not delivered; production boot with `redis://host` without a password is refused.
- **M-9 — Unauthenticated webhook endpoints are unthrottled and each costs a DB query**
  - Affected: `RATE_LIMIT_EXEMPT` in `server/src/index.ts`; `server/src/webhook-credentials.ts`; `/health`.
  - Attack: flood `/security-events/webhook` with random key ids and current timestamps, or hit `/health`, to exhaust the 10-connection pool.
  - Impact: logins and ingestion stall.
  - Fix: a failures-only per-IP limiter on the webhooks; nginx `limit_req`; a cached `/health`.
  - Test: 2,000 bad-key requests from one IP produce 429s after the threshold with no growth in `pg_stat_activity`.
- **M-10 — Nightly restore test runs as the Postgres superuser; backups are not signed**
  - Affected: `ops/lib/common.sh` (`restore_check`), `deploy/backup.env.example`.
  - Attack: whoever holds the app role creates a function with a CHECK constraint that calls it. The nightly superuser restore executes it (for example `COPY … TO PROGRAM`), giving OS code execution on the database host. Separately, write access to offsite storage lets someone plant a forged backup with a valid checksum.
  - Fix: a dedicated non-superuser CREATEDB role for restore tests; sign backups (minisign or ssh-sig) with an off-server key and verify before restore.
  - Test: an app-role object calling a function in a CHECK constraint does not run with superuser rights during `restore_check`; an unsigned dump is refused.
- **M-11 — SMTP does not require TLS**
  - Affected: `server/src/mailer.ts` (no `requireTLS`).
  - Attack: an on-path attacker strips STARTTLS and captures the SMTP credentials, plus reset and invite links.
  - Fix: `requireTLS: !smtpSecure`, with an explicit opt-out.
  - Test: a mock server without STARTTLS receives no AUTH or DATA.
- **M-12 — Audit log is mutable and has gaps**
  - Affected: `server/src/db/schema.sql` (`audit_log`, `ON DELETE CASCADE`); login, reset, logout and refresh-reuse paths.
  - Problem: failed logins, completed resets, logouts and refresh-token reuse are not audited. An app-role holder can edit or delete rows.
  - Fix: add the events; an append-only trigger and hash chain (as in the agent layer); drop the cascade.
  - Test: each event produces a row; `UPDATE audit_log` as the app role fails.
- **M-13 — Shell-command analyzer relies on an incomplete option denylist (latent)**
  - Affected: `packages/agent-identity/src/tools/shell.ts` (`DANGEROUS_OPTION`, `CONFIG_KEYS`).
  - Problem: options are matched by exact spelling, so equivalent spellings that common tools accept (joined short options, abbreviated long options) are not covered.
  - Attack: a tenant admin allowlists a tool, and the agent passes a code-executing or output-redirecting option in an unlisted spelling.
  - Impact: command execution on the tool host. This is latent: no shipped route or skill calls `runShell`, and the default allowlist is empty.
  - Fix: per-command allowlists of permitted options, parsing option syntax; deny everything else.
  - Test: equivalent spellings of each denied option are refused.
- **M-14 — Cloud analyzer misses secret-reading and credential-issuing actions (latent)**
  - Affected: `packages/agent-identity/src/tools/analyzers.ts` (`CLOUD_CRITICAL`).
  - Problem: `secretsmanager:BatchGetSecretValue`, `ssm:GetParametersByPath` and `ssm:GetParameterHistory`, and `sts:GetFederationToken` and `sts:GetSessionToken` count as reads.
  - Fix: deny these action families, or allowlist read actions.
  - Test: each action returns BLOCK `cloud.security_critical`.
- **M-15 — HTTP read permission can make writes via method-override headers**
  - Affected: `packages/agent-identity/src/tools/analyzers.ts`.
  - Problem: a GET carrying `X-HTTP-Method-Override: DELETE` is classified as `tool.http:read`.
  - Fix: refuse or re-classify override headers; refuse a body on GET/HEAD.
  - Test: such a call needs write permission.
- **M-16 — Any agent can permanently break firewall-decision chain verification**
  - Affected: `packages/agent-identity/src/tools/gateway.ts` (`target.slice(0, 200)`); `packages/agent-identity/src/firewall/log.ts`.
  - Problem: a split surrogate pair is hashed as-is but stored as U+FFFD, so verification fails at that row forever and masks later tampering.
  - Fix: truncate on code points / `toWellFormed()` before hashing and storing.
  - Test: a row with a split surrogate still verifies after a round trip through Postgres.

### LOW

| ID | Affected | Problem → fix (test) |
|---|---|---|
| L-1 | `/auth/change-password` | Pending reset link survives a password change → clear `reset_token_hash` (reset after change → 400). |
| L-2 | `/users/:id/role`, `DELETE /users/:id` | Last-admin check is a TOCTOU race → transaction + `FOR UPDATE` (parallel demotions leave ≥1 admin). |
| L-3 | `passwordField` | 8-char minimum, bcrypt silently truncates at 72 bytes, no breach check → ≤72 bytes, min 10–12, HIBP/zxcvbn (73-byte password → 422). |
| L-4 | `resolveSessionUser` → agent management routes | Blocked/read-only tenants can still write agent config → apply access state to non-GET. |
| L-5 | `/security-events/webhook` | Authenticated sensor: unbounded `provider`/`ip`/`os`, deep nesting → 500 and retries → clip/validate, hash raw body for ids. |
| L-6 | Alert id derivation, `POST /alerts` | Predictable id with a public default key; analysts may create `SEC-…` ids and pre-empt a detection → keyring-derived key, forbid prefix. |
| L-7 | WebSocket | No per-user/tenant connection cap, no backpressure → cap 10/user, close at 1 MB buffered. |
| L-8 | `frontend/next.config.mjs` | CSP `script-src 'unsafe-inline'` and `*.paddle.com` on every page → nonces; Paddle only when billing is configured. |
| L-9 | `GET /health` | Discloses version, mode, AI provider → public `status` only. |
| L-10 | `integrations/custom-legion.py` | Accepts `http://` hook URLs → refuse unless overridden. |
| L-11 | `/auth/register` | Verification URL logged whenever not production → gate on `DEV_LOG_AUTH_LINKS`. |
| L-12 | `deploy/legion.service`, `deploy/legion-backup.service` | Service can rewrite its own code; backup job runs as the same user and holds the superuser URL → read-only code, separate backup user, more systemd hardening. |
| L-13 | `ops/*.sh` | Database URLs with passwords in argv (`/proc/*/cmdline`) → `PGPASSFILE`. |
| L-14 | `scripts/try-local.mjs` | Hardcoded embedded-Postgres superuser password; `.env` written 0644 and overwrites a real one → random password, 0600, refuse to overwrite. |
| L-15 | `config.ts` | Remote database without SSL allowed in production → refuse unless overridden. |
| L-16 | Reset/invite/verify links | One-time tokens in the URL query end up in nginx access logs → fragment + POST, or a log format without args. |
| L-17 | Agent-layer `verifyChain` | Loads a whole table into memory → stream in batches. |
| L-18 | Agent `/token` vs suspension | Token issued in a race with suspension can revive on resume → lock identity row. |
| L-19 | Tool tickets | Stay valid ≤ ticket TTL after permission removal or a risk hold → revoke on change. |
| L-20 | Agent HTTP redirects | Credential headers forwarded across origins → strip on cross-origin redirect. |
| L-21 | `secrets-migration.ts` | `LIKE 'lsb1.<id>.%'` treats `_` as a wildcard → `split_part` comparison. |
| L-22 | `paddle.ts` | Portal fetch has no timeout and no `redirect:"error"` → add both. |
| L-23 | Prompt guard | Classification is linear now, but runs synchronously; multi-MB tool outputs still cost on the order of seconds on the event loop → cap/chunk off the main thread. |

### INFO

- An `mfa_token` is reusable for 5 minutes (each use still needs a fresh TOTP).
- `invite_url` is returned in API responses on self-hosted installs without SMTP.
- **File upload/download:** none exists anywhere (no multer, `sendFile`, static serving, or user-controlled paths).
- **Docker:** no Dockerfile or compose file exists; `OPENROUTER.md` references a `docker-compose.yml` that does not exist.
- **Dependencies:** `npm audit --omit=dev` reports no high or critical advisories (two moderates, not reachable).

## Areas reviewed and found sound (summary)

- **JWT:** HS256 pinned on sign and verify, 15-minute access tokens. Purpose tokens (MFA, checkout) are refused as sessions everywhere, including the WebSocket and the agent layer.
- **One-time tokens:** reset, invite and verify tokens are SHA-256-hashed 256-bit values, consumed atomically with expiry.
- **MFA:** TOTP replay protection, per-user failure limiter, sealed seeds (AES-256-GCM, HKDF, key-id AAD), fail-closed on key problems.
- **Cookies:** HttpOnly and Secure (enforced in production), Lax/Strict SameSite, and an Origin guard.
- **Tenant isolation:** audited and fixed earlier today, guarded by static and attack tests.
- **Wazuh webhook:** HMAC over the raw body, freshness, atomic nonce replay store, constant-time comparison, and tenant taken only from the credential.
- **Paddle webhook:** raw-body HMAC with fail-closed behaviour.
- **Outbox:** transactional, with fenced leases.
- **Email content:** HTML escaped, headers CRLF-safe.
- **AI:** fixed provider URLs, redaction, fenced untrusted content, output stripped of markup, rendered as text only.
- **SQL:** fully parameterised.
- **Database:** TLS verified by default; privileged role refused in production.
- **Backups:** age public-key encryption with the private key off the server.
- **Frontend:** no `dangerouslySetInnerHTML`, tokens not in localStorage, no open redirects.
- **Agent layer:** credentials stored as SHA-256 of 256-bit secrets, compared in constant time. Owner role ceilings, single-use tickets bound to a digest, SSRF re-checked after DNS and on every redirect.
