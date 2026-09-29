# Legion — Production-Readiness Audit (2026-09-29)

**Roles:** Principal Software Architect · Application Security Engineer · SaaS Reliability Engineer
**Scope:** the full codebase in `Legion-2026-09-29-final-audit.zip` (≈40k lines: `server/`, `frontend/`,
`packages/agent-identity/`, `ops/`, `deploy/`, `integrations/`, `.github/`) plus the current state of the
GitHub repository `abdumannopp/legion-`.
**Method:** I read the code and runtime configuration directly. Earlier audit documents (`SECURITY-AUDIT-*.md`,
`AUDIT-2.md`, `HISOBOT-*.md`) were ignored, and nothing is credited because a document says it is done.
**Code changes:** none. This file is the only addition.

> Paths below are relative to the zip root `legion/` unless prefixed `repo:` (the GitHub repository).
> Line numbers refer to the audited snapshot.

**Verification performed**

- Static review of every server module, the agent-identity package's auth, firewall, tool, skill, schema and
  routing code, the frontend's security-relevant code (API client, CSP, Paddle), ops scripts, systemd, nginx and CI.
- One runtime check, reproduced: the login endpoint's "dummy hash" timing defence (see P1-14). `bcryptjs@3` returns
  `false` for the shipped dummy hash in **~1 ms**, while a real cost-12 hash takes **~350 ms**.
- Not executed: the Postgres-backed test suites (`npm test`, `test:security`, `assess`). They need a provisioned
  database and a full install. Where a claim depends on runtime behaviour, it says so.

---

## 1. Executive summary

**Verdict: not ready for production SaaS traffic yet. The security core is unusually strong; the gaps are in
delivery, operations, billing integrity and data lifecycle.**

**What is genuinely good (verified in code):**

- **Sensor webhook authentication.** Each credential has its own secret. The HMAC covers
  `v2.<ts>.<nonce>.<raw body>`. Replay protection uses an atomic nonce insert. Comparison is constant-time, and an
  unknown key costs the same as a known one. The tenant is taken from the credential, never from a header
  (`server/src/webhook-auth.ts`, `server/src/webhook-credentials.ts`).
- **Sessions.** Access JWTs last 15 minutes. Refresh tokens are rotated, hashed and grouped into families with
  reuse detection. `token_version` bumps on password or role change. Cookies are httpOnly, and the refresh cookie
  is SameSite=Strict and path-scoped (`server/src/sessions.ts`, `server/src/index.ts:96-140`).
- **One-time tokens.** Reset, invite, verify and setup tokens are stored as SHA-256 hashes and consumed with a
  single conditional `UPDATE`, so they are race-free.
- **Secrets at rest.** AES-256-GCM with per-purpose HKDF subkeys, record-bound AAD and a versioned keyring with
  rotation (`server/src/secret-box.ts`).
- **MFA.** TOTP has replay protection (`mfa_used_counters`) and bcrypt-hashed recovery codes. An unreadable seed
  fails closed.
- **Network edge.** CORS is an exact allow-list. An Origin guard covers state-changing requests. WebSocket
  handshakes check Origin. Only named proxies are trusted.
- **Transactional outbox.** Delivery uses leases, fencing and dead-letter handling. The realtime cursor is backed
  by Postgres.
- **AI.** Models get no tools. Untrusted data is fenced. Secrets are redacted, input and output are bounded, and
  a circuit breaker stops calls after repeated failures.
- **Agent firewall.** Decisions fail closed and are hash-chained. Machine principals are confined to `/agent/v1`.
- **Backups and CI.** Backups are encrypted with age and restore-tested. The CI release gate is well designed.

**What blocks production (top items):**

1. **P0: the deployable system is not in version control.** The GitHub repository holds only docs plus a stale
   Docker path that cannot build or boot against the current code. CI therefore never runs.
2. **Alert pipeline durability.** A Legion restart or outage of more than about 10 seconds permanently loses Wazuh
   alerts. Boot-time migrations take `ACCESS EXCLUSIVE` locks on `alerts`/`users`/`tenants` on every start.
3. **Billing integrity.** The server never validates which price was bought. A late event from a different
   subscription can overwrite the tenant's current one. The subscription gate does not cover the AI-agent
   surface, and AI spend has no durable budget.
4. **Operations.** A crashed API child process is invisible to systemd. There are no metrics, structured logs or
   error tracking. Backups have a 24-hour recovery point (RPO) and no point-in-time recovery (PITR).
5. **Data lifecycle.** The published SaaS privacy terms promise deletion within 30 days and backup expiry within
   14 days. The code has no deletion path, the append-only audit tables make deletion impossible, and backups are
   kept for up to 12 months.

| Severity | Count | Meaning |
|---|---|---|
| **P0** | 1 | Blocks any production deployment |
| **P1** | 14 | Must fix before GA / paid SaaS / scaling past one instance |
| **P2** | 19 | Hardening; schedule within the next quarter |

---

## 2. Findings index

| ID | Sev | Area | Title |
|---|---|---|---|
| P0-1 | P0 | Delivery / Docker | Application source, CI and deploy assets are not in the repo; the committed Docker path is broken and unsafe |
| P1-1 | P1 | Wazuh / alert pipeline | Alerts are permanently lost during any Legion outage or restart longer than ~10 s; large events are dropped |
| P1-2 | P1 | PostgreSQL / migrations | Boot-time migrations lock hot tables on every start, in one transaction, with no lock timeout or versioning |
| P1-3 | P1 | API security / rate limiting | Unauthenticated traffic to the sensor webhook (and `/health`) is exempt from all rate limiting |
| P1-4 | P1 | Billing | The Paddle webhook grants access for any price or quantity; the client picks the price ID |
| P1-5 | P1 | Billing | One subscription row per tenant: events from another subscription overwrite the current one |
| P1-6 | P1 | Billing / RBAC | The subscription gate is not applied to the AI-agent surface (`/agents`, `/skills`, `/firewall`, `/agent/v1/*`…) |
| P1-7 | P1 | Billing / AI Copilot | AI quotas are in-memory, per instance and per minute only; no tenant or plan budget |
| P1-8 | P1 | Sessions | Refresh from several tabs at once is treated as token theft; all sessions are revoked |
| P1-9 | P1 | Deployment / reliability | `npm start` under systemd runs `concurrently`: an API crash is never restarted; `NODE_ENV` unset |
| P1-10 | P1 | Logging / monitoring | No structured logs, access log, metrics, tracing or error tracking; `/health` is shallow |
| P1-11 | P1 | Multi-tenant isolation | Isolation relies only on application `WHERE` clauses; no row-level security (RLS); runtime role owns all tables |
| P1-12 | P1 | Privacy / data handling | No tenant or user deletion path; append-only audit tables block deletion; backups outlive the promised period |
| P1-13 | P1 | Backups / recovery | Nightly logical dump only (RPO ≤ 24 h+); no PITR/HA; off-site copy and restore test optional |
| P1-14 | P1 | Authentication | The login timing defence is broken (verified): unknown emails answer in ~1 ms vs ~350 ms |
| P2-1 | P2 | MFA / auth | MFA changes don't revoke sessions or notify; no enforced MFA; step-up endpoints not throttled |
| P2-2 | P2 | Sessions | Refresh expiry slides forever; no session list or "sign out other devices" |
| P2-3 | P2 | Auth / email abuse | Global email enumeration via invites; unverified sign-ups squat emails; phishable invite subjects |
| P2-4 | P2 | RBAC | "At least one admin" and email caps are check-then-act without locking |
| P2-5 | P2 | API / DB | `limit=abc` → 500; unbounded `offset` and asset lists; unindexed `LIKE` search |
| P2-6 | P2 | DB scalability | Per-tenant alert writes serialise on the `tenants` row (`alert_seq`) |
| P2-7 | P2 | Performance | 4–5 DB round trips per API request before the handler; per-request activity writes; global audit-chain lock |
| P2-8 | P2 | Redis / WebSocket | One global pub/sub channel carrying alert content; no socket caps, liveness pings or back-pressure |
| P2-9 | P2 | Headers / proxy | Dashboard CSP allows `'unsafe-inline'` scripts; HSTS never sent on self-hosted; nginx has no `limit_req`; CDN/LB breaks client IPs |
| P2-10 | P2 | Config | `DEPLOYMENT_MODE` and numeric env vars are unvalidated; production strictness keyed to `NODE_ENV` |
| P2-11 | P2 | Auth / crypto | Single HS256 key with no `kid`, `iss` or `aud`; key rotation signs everyone out |
| P2-12 | P2 | Audit integrity | `audit_log` is mutable; append-only triggers can be dropped by the table-owning runtime role |
| P2-13 | P2 | Agent firewall / MCP / A2A | Firewall, behaviour and security-event hooks not wired to alerting; tool tickets advisory; `sweep` unscheduled |
| P2-14 | P2 | AI / privacy | No OpenRouter data policy; global circuit breaker trippable by one tenant; `/health` discloses provider and version |
| P2-15 | P2 | API | Mock provider `/security-events/sync` creates fake high-severity alerts (and emails) in production |
| P2-16 | P2 | DB growth / privacy | `sent` alert emails, audit and decision logs grow forever; no retention jobs |
| P2-17 | P2 | Supply chain / build | Two divergent lockfiles; runtime depends on a devDependency; build artefacts in the archive |
| P2-18 | P2 | Secrets | All secrets in plaintext `.env` (DB password twice); dev key derived from JWT stays decrypt-capable |
| P2-19 | P2 | Proxy / HTTP | Node `keepAliveTimeout` (5 s) is shorter than nginx upstream keep-alive → sporadic 502s |

---

## 3. Detailed findings

### P0-1 — Application source, CI and deploy assets are not in version control; the committed Docker path is broken and unsafe

**Risk.** The GitHub repository (`repo:`) contains only Markdown, a root `package.json`, `install.sh` and three
compose files. `server/`, `frontend/`, `packages/`, `ops/`, `deploy/`, `integrations/` and `.github/` exist only in
uploaded zip files. As a result:

- No code review trail exists, and security fixes cannot be patched or reverted reliably.
- The CI security gate (`.github/workflows/ci.yml`) never runs.
- No release is reproducible.
- An auditor or customer cannot tell which build is in production.

The committed deployment path is also incompatible with the current code:

- `repo:docker-compose.yml` builds `./server` and `./frontend`, which do not exist in the repo. The zip contains no
  Dockerfile at all.
- Even with the sources present, the backend would refuse to boot. The compose file sets no
  `LEGION_ENCRYPTION_KEYS`, and `server/src/config.ts` throws when it is missing.
- The API binds `127.0.0.1` by default (`LEGION_BIND_ADDRESS`), so inside a container it is unreachable through
  the published port.
- It publishes the API (`8000`) and dashboard (`3000`) on all host interfaces over plain HTTP, with
  `COOKIE_SECURE=false`.
- It connects the API as the Postgres **superuser** (`POSTGRES_USER`).
- It runs Redis with no password.
- `repo:docker-compose.monitoring.yml` mounts a non-existent `./monitoring/prometheus.yml`, publishes `9090`
  publicly, and scrapes an API that has no metrics endpoint.
- `repo:install.sh` writes secrets for the old scheme (`SECURITY_EVENT_WEBHOOK_SECRET` as an auth secret). It
  claims reset links are printed to the log; in current code they are not, unless `DEV_LOG_AUTH_LINKS=true`.
- README/INSTALL in the repo describe Docker. The zip's README describes `npm run setup` and systemd.

**Evidence.** `repo:docker-compose.yml` (backend `build: ./server`, `ports: "${API_PORT:-8000}:8000"`, no
`LEGION_ENCRYPTION_KEYS`); `repo:docker-compose.prod.yml` (only sets `NODE_ENV`); `server/src/config.ts:365-375`
(refuses to start without a keyring); `server/src/config.ts:54` (bind default); `repo:git log` (a single commit,
"Add files via upload", 23 files).

**Fix.**

1. Commit the zip contents to the repository on a branch and open a PR. Exclude `node_modules`, `__pycache__`,
   `*.tsbuildinfo` and `packages/agent-identity/assessment/results*`. Remove the stale root
   `package-lock.json`/`install.sh`/compose files, or rewrite them.
2. Enable branch protection on `main`, with the `Release gate` job as a required check (the workflow already
   exists).
3. Choose one supported deployment path and delete the other:
   - (a) systemd + nginx (current code), with the fixes in P1-9; or
   - (b) containers: multi-stage Dockerfiles for `server` (`node dist/index.js`, non-root user, read-only root
     filesystem) and `frontend` (`output: "standalone"` is already set). Compose would then provide
     `LEGION_ENCRYPTION_KEYS`, `LEGION_BIND_ADDRESS=0.0.0.0`, `TRUSTED_PROXIES=<proxy network CIDR>`, the app DB
     role from `provision-cli`, `NODE_ENV=production` and Redis `requirepass`, and publish only the reverse proxy
     on 443.
4. Tag releases, and have `/health` report the git SHA.

**Dependencies / migration risk.** None on the data side. Existing installs deployed from zips must be
reconciled: diff each deployed tree against the committed tree before the first release built from the repo.

---

### P1-1 — Alerts are permanently lost during any Legion outage or restart longer than ~10 s; large events are dropped

**Risk.** This is the core promise of a SIEM-adjacent product, and it has several ways to lose data:

- **Short retry window.** `integrations/custom-legion.py` tries 4 times with 1/2/4 s back-off, plus 10 s timeouts,
  then logs `not delivered` and exits. Nothing is spooled. A deploy, a crash (see P1-9), a Postgres failover or
  the migration lock (P1-2) longer than the retry window silently deletes security telemetry.
- **Oversized events.** The API's JSON body limit is 256 KB. A Wazuh alert with a large `full_log` gets a 413,
  which the script classes as `fatal`, so the event is dropped.
- **Limited per-tenant throughput.** Ingestion for one tenant is serialised by the `alert_seq` row lock (P2-6).
  Integratord bursts (thousands of events per second) back up into the script's retries, and those eventually give
  up.
- **Process-per-alert model.** Wazuh integratord runs the script once per alert: one Python process per event.

**Evidence.** `integrations/custom-legion.py:52-53,104-113,139-142`; `server/src/index.ts:51-52`
(`limit: "256kb"`); `server/src/index.ts:1509-1575`; `server/src/db/schema.sql:340-362`.

**Fix.**

- **Short term.** Make the script durable. On final failure, write the signed payload to a spool directory, for
  example `/var/ossec/tmp/legion-spool/`. Drain the spool from a small systemd timer or cron job that re-signs
  each event with a fresh nonce and timestamp. This is safe because alert IDs are deterministic HMACs
  (idempotent).
- **Large events.** Truncate `full_log` client-side to about 64 KB before signing, and keep the 413 fallback as
  retryable after truncation.
- **Medium term.** Offer a pull-based connector: read from the Wazuh Indexer/OpenSearch with a persisted cursor.
  Alternatively, accept batched NDJSON: one signed request carrying N events.
- **Server side.** Split ingestion from alert creation: `POST` writes the raw event to an `ingest_queue`
  (append-only, no tenant row lock) and returns 202. A worker then does dedup, asset upsert and outbox. Add
  metrics for webhook accept/reject/latency and ingest queue depth.

**Dependencies / migration risk.** A new table and a worker. The alert ID derivation must not change, because
dedup across the transition depends on it. Coordinate with P1-2, so a migration never blocks ingestion, and with
P1-3.

---

### P1-2 — Boot-time migrations lock hot tables on every start, in one transaction, with no lock timeout or versioning

**Risk.** `migrate()` runs on every boot of every instance. It sends the entire `schema.sql`, plus the agent
schema, as one multi-statement simple query. PostgreSQL runs such a string as **one implicit transaction**, so
every lock is held until the last statement ends. Several statements re-run on every boot and take
`ACCESS EXCLUSIVE` locks:

- `ALTER TABLE alerts DROP/ADD CONSTRAINT alerts_ai_explanation_source_check` re-validates by scanning the whole
  `alerts` table.
- `ALTER TABLE notification_outbox DROP/ADD CONSTRAINT …kind_check` scans the whole outbox, which is never pruned
  (P2-16).
- The same pattern repeats on `tenants` and `users`.
- `ALTER TABLE alerts ALTER COLUMN seq SET NOT NULL` locks `alerts` even when it is a no-op.
- `CREATE OR REPLACE TRIGGER` runs on `alerts`.
- The `DO` block runs `SELECT … FROM alerts WHERE seq IS NULL`, a sequential scan.

There is no `lock_timeout`. If any long query holds a conflicting lock, the `ALTER` waits, and every new request
touching those tables queues behind it. That is a full outage for the duration, and it recurs on every restart
and every rolling-deploy pod. The approach has other weaknesses:

- No migration version table means no ordering guarantees and no way to know which schema a database has.
- Destructive changes cannot be expressed safely.
- The runtime role must own every table to run DDL, which feeds into P1-11 and P2-12.

**Evidence.** `server/src/db/pool.ts:143-163`; `server/src/db/schema.sql:250-251, 316-317, 360-384`;
`packages/agent-identity/src/schema.ts` (same pattern).

**Fix.**

1. Adopt a versioned migrator such as `node-pg-migrate`, `graphile-migrate` or Sqitch, with a
   `schema_migrations` table. Baseline the current `schema.sql` as version 1.
2. Run migrations as a **separate deploy step**, for example `node dist/db/migrate-cli.js`, under a dedicated
   migration/owner role. The API role then gets only DML privileges.
3. In every migration: `SET lock_timeout = '3s'` with retry; `ADD CONSTRAINT … NOT VALID` followed by
   `VALIDATE CONSTRAINT`; `CREATE INDEX CONCURRENTLY`, which runs outside a transaction.
4. Remove all "drop and re-add every boot" statements.

**Dependencies / migration risk.** High care but mechanical. The baseline must match production exactly: run
`pg_dump --schema-only` on each environment and diff it. The deploy scripts and systemd units must run
migrations before starting the API. This is a prerequisite for P1-11 (RLS) and for splitting the owner and
runtime roles.

---

### P1-3 — Unauthenticated traffic to the sensor webhook (and `/health`) is exempt from all rate limiting

**Risk.** `RATE_LIMIT_EXEMPT` skips the API limiter for `/security-events/webhook` and `/health`, and the
principal resolver also skips them. The exemption is justified for *authenticated* sensor traffic, but it applies
before authentication:

- Anyone can send well-formed headers with a fake `whk_…` key ID and a current timestamp. Each such request costs
  up to 256 KB of JSON parsing, a Postgres query and an HMAC over the body, and nothing throttles it.
- `/health` runs a DB query per call, also unthrottled.
- nginx adds no `limit_req` (P2-9).

This is a cheap, remotely reachable way to exhaust the DB pool (`DB_POOL_MAX=10` by default) and take down login
and ingestion for every tenant.

**Evidence.** `server/src/index.ts:71-75, 344-363, 1509-1523`;
`server/src/webhook-credentials.ts:63-80` (DB lookup before the signature verdict).

**Fix.**

- Add a limiter keyed by client IP that counts only **failed** webhook authentications (`failuresOnly`, for
  example 30 per minute per IP), plus a generous per-`key_id` limiter after authentication (for example 50k per
  minute) as a runaway-sensor guard.
- Cache `/health` for 1–2 s in-process, or split it into `/livez` (no DB) and a token-protected `/readyz`.
- Add an nginx `limit_req` zone for `/api/security-events/webhook` and `/api/auth/`.
- Consider a raw-body size gate on the webhook before JSON parsing.

**Dependencies / migration risk.** Low. Calibrate against real Wazuh volume. Authenticated traffic must stay
effectively unthrottled, and the sensor script must treat 429 as retryable (it already does).

---

### P1-4 — The Paddle webhook grants access for any price or quantity; the client picks the price ID

**Risk.** The dashboard opens Paddle.js with a `priceId` from `NEXT_PUBLIC_PADDLE_PRICE_ID`. Both the value and
the call are client-side. The webhook maps *any* `subscription.*` event with status `active` or `trialing` to full
access, and stores `items[0].price.id` without checking it. An admin can therefore get full access by opening a
checkout for any other price in the vendor catalogue: a cheaper plan, a test or legacy price, a different product
or a heavily discounted price. Quantity (seats) is ignored as well, because the server has no plan model.

**Evidence.** `frontend/lib/paddle.ts:47-57, 91`; `server/src/index.ts:1311` (checkout token), `1363-1426`
(status mapping; `paddle_price_id` stored unchecked at `1412`).

**Fix.** Keep a server-side allow-list: a `PADDLE_PRICE_IDS` map from price to plan. In the webhook:

- Reject, or mark `unrecognised_plan` and deny access for, any subscription whose items are not an allowed price.
- Validate `items[].quantity`, `currency` and the product ID.

Create the checkout **server-side**: `POST /billing/checkout` returns a Paddle transaction created with the
server's allowed price, so the browser never chooses the price. Persist `plan` and `seats` on the subscription
row, and enforce them (see P1-7 and seat limits on `/users/invite`).

**Dependencies / migration risk.** Backfill `plan` for existing subscriptions from `paddle_price_id`. Coordinate
with P1-5, which changes the same table. Test in the Paddle sandbox with discount codes and every catalogue
price.

---

### P1-5 — One subscription row per tenant: events from another subscription overwrite the current one

**Risk.** `subscriptions` has primary key `tenant_id`, and `applySubscriptionEvent` upserts `ON CONFLICT
(tenant_id)`, replacing `paddle_subscription_id`. `getSubscriptionByPaddleId` only finds the *current* ID. Here
is how that fails:

1. A customer cancels subscription A at period end and immediately buys B. Both bind to the same tenant through
   the checkout token.
2. When A's `subscription.canceled` arrives later (its `occurred_at` is newer), the lookup by A's ID misses.
3. The code re-binds through the non-expiring checkout token and overwrites the row with `canceled`.
4. The paying tenant is **blocked**.

Two concurrent checkouts produce the same flip-flop.

**Evidence.** `server/src/db/schema.sql:174-189`; `server/src/store.ts:720-765`;
`server/src/index.ts:1363-1426`.

**Fix.** Key the table by `paddle_subscription_id` with a `tenant_id` column, allowing many rows per tenant. Apply
the `last_event_at` ordering per subscription. Compute `accessState` as the best state across the tenant's
subscriptions (any `active`/`trialing` → ok). Refuse a new checkout while an active subscription exists, and send
the customer to the Paddle portal for plan changes instead.

**Dependencies / migration risk.** Schema change, which needs the versioned migrations from P1-2. Backfill is
trivial: current rows become one row each. `accessState`, `/billing/subscription` and the frontend billing page
must change together.

---

### P1-6 — The subscription gate is not applied to the AI-agent surface

**Risk.** `enforceAccess` runs only inside `authenticate()` for routes in `index.ts`. The agent-identity routers
use their own guards (`requireHuman`, `requireMachine`, `requirePermission`), and those never consult
`accessState`. They are mounted at `/agents`, `/service-accounts`, `/firewall`, `/prompt-guard`, `/tools`,
`/behavior`, `/kill-switch`, `/a2a` and `/skills`, and at `/agent/v1` for token, messages, tools and skills. Only
the four data routes in `server/src/agents.ts` call `allowed()`.

A trial-expired, canceled or past-due tenant can therefore still:

- create agents and credentials;
- mint agent tokens;
- invoke security skills, which call the **paid** AI provider through `skillModel`;
- run the A2A and tool-authorisation flows.

**Evidence.** `server/src/agents.ts:167-180` (mounting), `208-213` (`allowed` used only by the local routes);
`packages/agent-identity/src/skills/routes.ts:60`; `server/src/index.ts:207-219`.

**Fix.** Mount a gate middleware before `agentLayer.mount(app)`:

- Resolve `req.principal.tenantId` and call `accessState`.
- `blocked` → 402 for everything except `GET` on audit and history and the **kill switch**. Stopping agents must
  always stay possible.
- `readonly` → allow only `GET`.
- Also refuse `/agent/v1/token` issuance for blocked tenants.

**Dependencies / migration risk.** Low. Add tests for each mounted prefix × access state, and an explicit
allow-list for kill-switch routes.

---

### P1-7 — AI quotas are in-memory, per instance and per minute only; no tenant or plan budget

**Risk.** `consumeAiQuota` is a per-process `Map` limited to 30 calls per minute per tenant. It resets on restart,
multiplies with the number of instances, and has no daily or monthly budget, token accounting or plan tier. In
hosted mode any admin, including a trial tenant, can enable AI (`PATCH /ai/settings`). With unlimited sign-ups
(each needs only a verified email), the operator's OpenRouter/Groq bill is uncapped. The circuit breaker is also
per instance and global (P2-14).

**Evidence.** `server/src/ai-policy.ts:52-70`; `server/src/index.ts:1042-1050`; `server/src/agents.ts:119-125`
(skills share the quota).

**Fix.**

- Add an `ai_usage` table (tenant, day, calls, input chars or tokens, output tokens, provider, cost estimate)
  written after each call.
- Enforce per-plan monthly and daily budgets with a Redis or PG counter checked before the call. Give trials a
  small fixed budget.
- Expose usage on the billing page.
- Keep a provider-side spend cap as the final backstop.

**Dependencies / migration risk.** Needs the plan model from P1-4. The new table is additive.

---

### P1-8 — Refresh from several tabs at once is treated as token theft; all sessions are revoked

**Risk.** The access cookie is shared by all tabs and expires for all of them at once. Each tab de-duplicates its
own refreshes (`refreshInFlight`), but tabs do not coordinate with each other. This sequence follows:

1. Tab A rotates the refresh token.
2. Tab B's refresh, already in flight with the old cookie, finds `rotated_at` set.
3. The server declares reuse and revokes the whole family, including A's new token.

Analysts who keep several dashboard tabs open will be logged out regularly. The real "reuse detected" signal also
becomes noise, which trains people to ignore it.

**Evidence.** `server/src/sessions.ts:89-100`; `frontend/lib/api.ts:113-130`.

**Fix.**

- **Server.** Record `replaced_by` on rotation. If a rotated token is presented again within a short grace
  window (for example 30 s) *and* its successor has not been used yet, return the same successor instead of
  revoking. Keep strict reuse detection outside the window.
- **Client.** Serialise refresh across tabs with `navigator.locks.request("legion-refresh", …)` and a
  `BroadcastChannel` notification.

**Dependencies / migration risk.** Add a nullable `replaced_by uuid` column. This changes a security control, so
extend `tests/sessions.test.ts` with concurrent-tab cases.

---

### P1-9 — systemd runs `npm start` → `concurrently`: an API crash is never restarted; `NODE_ENV` unset

**Risk.** `deploy/legion.service` runs `ExecStart=/usr/bin/npm start`. The root `start` script launches the API
and the web server under `concurrently`, which is a **devDependency**. Without `--kill-others`, `concurrently`
keeps running while any child is alive. If the API crashes (for example on an unhandled rejection), the dashboard
keeps the unit "active", so `Restart=on-failure` never fires and the API stays down with no alert. Ingestion stops
at the same time (P1-1).

The unit also sets no `NODE_ENV=production`, and `npm run setup` writes it only for SaaS. So on self-hosted
production:

- HSTS is never sent (`hstsEnabled()` requires `isProduction`).
- SMTP and `DATABASE_URL` checks are skipped.
- A privileged DB role only produces a warning.
- `npm install` must include dev dependencies for the service to start at all.

**Evidence.** `deploy/legion.service:27`; `package.json:13`; `server/scripts/setup.mjs:323-327`;
`server/src/edge.ts:128-130`; `server/src/index.ts:1650-1654`.

**Fix.** Ship two units:

- `legion-api.service`: `ExecStart=/usr/bin/node /opt/legion/server/dist/index.js`,
  `Environment=NODE_ENV=production`, `Restart=always`.
- `legion-web.service`: `node .next/standalone/server.js`.

Also:

- Add `process.on("unhandledRejection")` logging with an explicit exit code, so crashes are restarted.
- Add an external uptime check on `/health`.
- Make the shutdown's forced exit use a non-zero code.
- For zero-downtime deploys, run two API instances behind nginx with Redis enabled.

**Dependencies / migration risk.** Update DEPLOY-ONLINE.md. Test on a staging VM, because
`ProtectSystem=strict` and `ReadWritePaths` must still cover the setup-token file and backup status paths.

---

### P1-10 — No structured logs, access log, metrics, tracing or error tracking; `/health` is shallow

**Risk.** Every log is an unstructured `console.*` line:

- There is no per-request access log.
- The `x-request-id` the agent layer sets is never logged, so no user-visible error can be correlated.
- There is no tenant context in logs.
- There is no `/metrics` endpoint. The only numbers are `/health/outbox` and `/health/backup`.
- There is no error tracker.
- `/health` checks only the DB. Redis connectivity, outbox worker liveness, the dead-letter count and the
  migration state are invisible.

For a security product with a durability promise, you cannot detect ingestion loss (P1-1), a stuck worker, or
DB-pool exhaustion (P1-3, P2-7).

**Evidence.** `server/src/index.ts:344-399`; there is no logger module; `repo:docker-compose.monitoring.yml`
references a missing config.

**Fix.**

- **Logging.** Use `pino` + `pino-http` with a request ID, tenant ID, principal type and latency, and redact
  secrets and tokens.
- **Metrics.** Use `prom-client` behind the existing `HEALTH_METRICS_TOKEN`: HTTP RED metrics per route, webhook
  accept/reject by cause, alerts ingested per tenant tier, outbox depth, oldest pending and dead count, DB pool
  wait and usage, Redis state, AI calls, latency and failures by reason, WebSocket connection count.
- **Tracing and errors.** Add OpenTelemetry traces for the ingest → outbox → realtime path, and Sentry (or
  similar) with PII scrubbing.
- **Alerting rules.** Webhook 5xx or reject spikes, outbox oldest pending > 5 min, any `dead`, backup health 503,
  DB pool saturation.

**Dependencies / migration risk.** Additive. Watch log volume and PII: keep alert text out of logs.

---

### P1-11 — Isolation relies only on application `WHERE` clauses; no row-level security (RLS); runtime role owns all tables

**Risk.** Every tenant query is hand-scoped (`tenant_id = $1`). I found no unscoped read or write reachable from a
request. By-ID lookups such as `findUserById` are cross-checked against JWT claims, and there are good regression
tests (`tenant-isolation-sweep`, `tenant-query-guard`, `cross-tenant-attacks`). But there is **no database-level
backstop**:

- No `ROW LEVEL SECURITY` exists in either schema.
- The API's `legion_app` role *owns* every table, so even future RLS would be bypassed unless it is `FORCE`d.
- Owning the tables also lets the role `DROP`/`ALTER` them and disable triggers (P2-12).

One missed `WHERE` in a future change, or one SQL-injection bug, exposes every tenant. Agent-identity tables use
`tenant_id text` without foreign keys to `tenants`.

**Evidence.** `server/src/db/schema.sql` (no RLS); `server/src/db/provision.ts:12-18, 85-123` (ownership is
transferred to the app role); `packages/agent-identity/src/schema.ts:10-11` (foreign keys only suggested).

**Fix.**

1. Split roles: `legion_owner` (DDL, migrations — P1-2) and `legion_app` (DML only, no ownership).
2. Enable `ALTER TABLE … ENABLE ROW LEVEL SECURITY` and `FORCE` on tenant tables, with a policy of
   `tenant_id = current_setting('app.tenant_id')::uuid`.
3. Set the tenant per request inside a transaction with `SELECT set_config('app.tenant_id', $1, true)`.
4. Give cross-tenant workers (outbox, prune, cursor heartbeat, webhook credential lookup) a separate narrowly
   granted role or `SECURITY DEFINER` functions.
5. Add foreign keys from agent tables to `tenants(id)` (as `uuid`).

**Dependencies / migration risk.** Large. Every `pool.query` call site must run inside a tenant-scoped
transaction. Postgres connection poolers such as pgbouncer must be in transaction mode. Roll out table by table,
starting with `alerts`, `assets`, `audit_log`, `webhook_credentials` and `users`. Stage it with policies in
permissive mode plus query logging, then enforce. Depends on P1-2.

---

### P1-12 — No tenant or user deletion path; append-only audit tables block deletion; backups outlive the promised period

**Risk.** The hosted privacy and terms text promise: "ask us to delete it and we will do so within 30 days.
Deleted data can remain in backups for up to 14 days." The code does not support this:

- **No deletion or export exists.** No endpoint, CLI or job deletes or exports a tenant or a user. Deactivation
  keeps everything.
- **Deletion is impossible even by hand.** `principal_audit_log` and `firewall_decisions` have `BEFORE UPDATE OR
  DELETE` triggers that raise an exception. `DELETE FROM tenants` cascades into core tables, but agent tables have
  no foreign keys, and the append-only rows **cannot be deleted without disabling triggers**. Those rows contain
  personal data: human `principal_name` is the user's **email**, plus IPs and user agents.
- **Backups outlive the promise.** Retention defaults to 14 daily + 8 weekly + **12 monthly** backups, so deleted
  data survives up to a year.
- **Nothing expires.** `alerts`, `audit_log`, sent outbox emails (with recipient and alert content) and refresh
  metadata grow forever (P2-16).

This is a contractual and GDPR-style exposure for the SaaS offering.

**Evidence.** `frontend/content/legal/saas.ts:92, 330`; `ops/prune-backups.sh:18`;
`packages/agent-identity/src/schema.ts:98-110, 168-175`; `server/src/agents.ts:130-140` (email used as the display
name).

**Fix.**

- Build a tenant offboarding job: export (JSON/CSV bundle), then delete in dependency order. For append-only
  chains, design per-tenant chains that can be **dropped as a unit** with a signed tombstone record kept in a
  platform-level log. Alternatively, store pseudonymous principal IDs in the chain and keep PII in a deletable
  side table.
- Build user-level erasure: pseudonymise `user_email` in `audit_log`.
- Add scheduled retention jobs per table and per plan.
- Either shorten backup retention to match the text (for example 14 daily only) or change the legal text to the
  real retention. Legal and engineering must agree on one number.

**Dependencies / migration risk.** Changing the audit-chain layout needs a migration and chain re-verification
tooling. Deleting data is irreversible, so require a two-step admin confirmation and keep an operator runbook.

---

### P1-13 — Nightly logical dump only (RPO ≤ 24 h+); no PITR or high availability; off-site copy and restore test optional

**Risk.** Backups are one `pg_dump` per night at 02:40 (`legion-backup.timer`):

- The worst-case data loss is about 24 hours of alerts and audit history.
- There is no WAL archiving or point-in-time recovery, and no replica or failover.
- The restore test runs only if `DATABASE_ADMIN_URL` is set. `BACKUP_UPLOAD_CMD` is optional, and a missing
  off-site copy is only a warning unless `BACKUP_REQUIRE_OFFSITE=true`.
- The encryption keyring and JWT secret (`server/.env`) are backed up by hand. Losing the server without them
  makes every MFA seed and webhook secret unreadable.

The backup scripts themselves are well built (age encryption, checksums, status file, alerting).

**Evidence.** `deploy/legion-backup.timer`; `ops/backup.sh:96-110, 150-170`; `server/src/config.ts:268-269`.

**Fix.**

- **SaaS.** Use managed Postgres with PITR (7–35 days) and a standby. Otherwise, pgBackRest or WAL-G with
  continuous WAL archiving to object storage.
- **Enforce the safety nets.** Make off-site upload and restore testing **required** in production
  (`BACKUP_RESTORE_TEST=required`, `BACKUP_REQUIRE_OFFSITE=true`).
- **Keys.** Keep `LEGION_ENCRYPTION_KEYS`/`JWT_SECRET` in a secret manager with its own backup.
- **Targets.** Define RPO/RTO in writing (for example RPO 5 min, RTO 1 h) and run quarterly restore drills from
  off-site copies.

**Dependencies / migration risk.** Infrastructure only. The recovery runbook (`RECOVERY.md`) must be updated for
PITR.

---

### P1-14 — The login timing defence is broken (verified)

**Risk.** Login compares the password against a dummy hash when the email is unknown, to equalise timing. The
dummy string is **64 characters**, while a valid bcrypt hash is 60, so `bcryptjs` returns `false` immediately.
Measured: unknown email ≈ 1 ms, known email ≈ 350 ms. Invited accounts (`password_hash = ""`) are also fast.
Anyone can enumerate which emails have Legion accounts, and which organisations use Legion, which enables targeted
credential stuffing and phishing. The per-account limiter does not stop this, because enumeration needs only one
request per email.

**Evidence.** `server/src/index.ts:535-540`; reproduced with `bcryptjs@3`.

**Fix.** At boot, compute `const DUMMY_HASH = bcrypt.hashSync(randomBytes(16).toString("hex"), 12)`. Use it
whenever the user is missing or `password_hash` is empty or not a 60-character `$2`-prefixed hash. Add a test
asserting similar latency, with a tolerance, for known and unknown emails. Apply the same idea to
`/auth/forgot-password`: send the mail through the outbox, not inline (P2-3).

**Dependencies / migration risk.** None.

---

### P2-1 — MFA changes don't revoke sessions or notify; no enforced MFA; step-up endpoints not throttled

- Enabling MFA leaves other existing sessions alive, which may include an attacker's. Disabling it notifies nobody.
  *Fix:* bump `token_version` and revoke other refresh families on enable and disable. Email the user on MFA
  disable, password change and recovery-code regeneration.
- There is no tenant policy "require MFA for admins" or "for all users". *Fix:* add `tenants.mfa_required` and
  gate `startSession` until enrolment is complete.
- `/auth/change-password`, `/auth/mfa/disable` and `/auth/mfa/recovery-codes` sit only under the general
  300/min/IP limiter. A stolen session can brute-force the current password to gain persistence. *Fix:* apply
  `authLimiter` plus a per-user failure limiter.
- The TOTP window of ±1 step with 5 failures per 5 minutes gives about 0.4% per day for an attacker who already
  has the password. *Fix:* exponential back-off and lockout notification after repeated MFA failures.
- Passwords need only 8 characters, with no breached-password check. *Fix:* check against HIBP k-anonymity or a
  local top-100k list.

*Evidence:* `server/src/index.ts:401, 668-723, 821-835`; `server/src/ratelimit.ts:302-339`.

### P2-2 — Refresh expiry slides forever; no session list or "sign out other devices"

Each rotation sets `expires_at = now + 30 days`, so an active session never ends. *Fix:* store `family_started_at`
and enforce an absolute lifetime (for example 30 days) plus an idle timeout. Add `GET/DELETE /auth/sessions`, which
can reuse `activeSessionCount`. *Evidence:* `server/src/sessions.ts:42, 141-148`.

### P2-3 — Global email enumeration via invites; unverified sign-ups squat emails; phishable invite subjects

- **Enumeration through invites.** Emails are unique across tenants, and `/users/invite` answers "That email
  address is already in use", which reveals that the address is a Legion user anywhere.
- **Email squatting.** Unverified hosted sign-ups are never cleaned up, so anyone can permanently reserve a
  victim's address and block future invitations to it.
- **Phishing through invite emails.** Invite subjects embed the attacker-chosen tenant name and are sent from the
  platform domain to arbitrary addresses (50 per hour per tenant, and tenants are unlimited), which is a
  phishing and reputation risk.
- **Timing oracle on password reset.** `forgot-password` sends SMTP inline, which creates a timing oracle.

*Fix:* return a neutral answer for invites to existing accounts, or support multi-tenant membership. Expire
unverified accounts after 48 h. Sanitise and length-limit tenant names in subjects, and add a per-platform cap on
invitations from young or unpaid tenants. Queue all auth mail through the outbox. *Evidence:*
`server/src/index.ts:787-802, 1060-1086`; `server/src/mailer.ts:200-233`.

### P2-4 — "At least one admin" and email caps are check-then-act without locking

Two admins demoting or deactivating each other at the same time can both pass `countOtherActiveAdmins`, leaving
zero admins. The invite, test-email and confirmation caps count audit rows and then act, so concurrent requests
can exceed them. *Fix:* in one transaction, lock the tenant's admin rows with `SELECT … FOR UPDATE`, or use a
serializable transaction. Take the counters from an atomic `UPDATE … RETURNING` or Redis `INCR`. *Evidence:*
`server/src/index.ts:1067, 1114, 1137-1167`.

### P2-5 — `limit=abc` → 500; unbounded `offset` and asset lists; unindexed `LIKE` search

- `Number("abc")` is `NaN`, which passes through `Math.min`/`Math.max` and becomes `LIMIT NaN`, a Postgres error
  and a 500. This affects `/alerts`, `/alerts/feed` and `/audit`.
- `offset` is unbounded: deep `OFFSET` scans.
- `listAssets` has no `LIMIT`, including through the agent API.
- `q` search uses `lower(title) LIKE '%…%'` with no trigram index.

*Fix:* validate query parameters with zod (as `/alerts/sync` already does). Use keyset pagination on
`(created_at, seq)`. Cap assets. Add `pg_trgm` GIN indexes. *Evidence:* `server/src/index.ts:869-893, 1170-1175`;
`server/src/store.ts:396-409, 626-637`.

### P2-6 — Per-tenant alert writes serialise on the `tenants` row (`alert_seq`)

The `alerts_assign_seq` trigger updates `tenants.alert_seq` on every alert insert **and update**. That holds the
tenant row lock until commit, across the asset upsert (with its 7-day subquery) and the outbox inserts. One
tenant's ingestion is strictly serial, and it contends with tenant setting writes and with webhook credential
`FOR UPDATE`. The trade-off is documented and gives gap-free cursors, but it caps per-tenant throughput at
roughly the inverse of the transaction time. *Fix:* keep the counter but shorten the transaction (P1-1 ingest
queue), or move to a per-tenant counter table so tenant settings don't contend. Benchmark with realistic Wazuh
bursts. *Evidence:* `server/src/db/schema.sql:340-362`; `server/src/outbox.ts:161-174`.

### P2-7 — 4–5 DB round trips per API request before the handler; per-request activity writes; global audit-chain lock

- For every cookie-authenticated request, the principal resolver loads the user, then `authenticate` loads the
  same user again, then `accessState` reads the subscription and the tenant.
- Agent requests do `findToken`, `host.getUser`, `touchActivity` (a write, throttled to once per 60 s) and
  firewall lookups.
- Principal-audit writes take a per-tenant advisory lock, and all anonymous failures share **one global chain
  lock** (`GLOBAL_CHAIN`).
- With `DB_POOL_MAX=10`, the pool saturates early.

*Fix:* cache the resolved user and access state on `req` or `res.locals` for the request's lifetime. Add a 5–10 s
in-process cache for `accessState`, invalidated by a Paddle webhook publish. Shard the anonymous chain by hour or
by IP-hash, or sample it more aggressively. Size the pool to about cores × 2–4 per instance and add pgbouncer.
*Evidence:* `server/src/index.ts:90, 186-258`; `packages/agent-identity/src/principal.ts:120-150`;
`packages/agent-identity/src/chain.ts:36-40`.

### P2-8 — One global pub/sub channel carrying alert content; no socket caps, liveness pings or back-pressure

- **Global channel.** All tenants publish full alert payloads (title, summary, IPs) to one Redis channel,
  `legion:realtime`. Every instance receives every tenant's data. Redis runs without auth or TLS in the shipped
  configs.
- **No socket caps.** There is no per-user or per-tenant limit on concurrent sockets, only 60 handshakes per
  minute per IP.
- **No liveness detection.** There are no WebSocket ping/pong frames, so half-open TCP connections linger until a
  send fails.
- **No back-pressure.** `socket.send` ignores `bufferedAmount`, so a slow consumer grows memory.

*Fix:* publish only `{tenant_id, alert_id, seq}` and let clients fetch through `/alerts/sync`, which removes alert
content from Redis. Alternatively, use per-tenant channels. Require a Redis password and TLS
(`rediss://`) in production. Cap sockets at about 10 per user and 500 per tenant. Add a 30 s ping/pong
terminate-on-miss, and drop or close sockets above 1 MB buffered. *Evidence:* `server/src/realtime.ts:34, 97-110,
319-322, 333-372`; `server/src/index.ts:1586-1645`.

### P2-9 — Dashboard CSP allows `'unsafe-inline'` scripts; HSTS never sent on self-hosted; nginx has no `limit_req`; CDN/LB breaks client IPs

- The dashboard CSP has `script-src 'self' 'unsafe-inline'`, so any HTML-injection bug becomes script execution.
  *Fix:* use nonce-based CSP through Next.js middleware (`headers()` plus the `nonce` prop), or `'strict-dynamic'`
  with hashes.
- HSTS is sent only when `NODE_ENV=production`, which self-hosted setups never set, and `deploy/nginx.conf` adds
  no HSTS after certbot. *Fix:* set HSTS in nginx on the 443 server block.
- nginx has no `limit_req`, `limit_conn` or request timeouts for `/api/`.
- `proxy_set_header X-Forwarded-For $remote_addr` is correct when nginx is the edge. Behind Cloudflare or a load
  balancer, though, every client appears as the LB's address, and the 10/min auth limiter locks out all users.
  *Fix:* document `real_ip_from` / `set_real_ip_from` for CDN deployments.

*Evidence:* `frontend/next.config.mjs:19-31, 43-45`; `server/src/edge.ts:128-130`; `deploy/nginx.conf`.

### P2-10 — `DEPLOYMENT_MODE` and numeric env vars are unvalidated; production strictness keyed to `NODE_ENV`

- `DEPLOYMENT_MODE` is cast without validation. A typo (`selfhosted`, `self_hosted`) makes `isSelfHosted()`
  false, which silently turns on **open public sign-up** and billing gating on a customer's private install.
- Numeric settings such as `ACCESS_TOKEN_MINUTES`, `REFRESH_TOKEN_DAYS`, `TRIAL_DAYS`, `DB_POOL_MAX`, `PORT` and
  `AUTH_RATE_LIMIT` go through `Number()` unchecked. `NaN` produces invalid JWT expiry or unlimited limits.
- Production safety depends on `NODE_ENV=production` (see P1-9).

*Fix:* parse the whole config with a zod schema at boot (an enum for the mode, integers with ranges). Add an
explicit `LEGION_ENV=production|staging|development` that is independent of `NODE_ENV`. *Evidence:*
`server/src/config.ts:37-41, 76, 102-103, 185`.

### P2-11 — Single HS256 key with no `kid`, `iss` or `aud`; key rotation signs everyone out

Access tokens, MFA challenge tokens and Paddle checkout tokens all share `JWT_SECRET`. Purposes are separated only
by a `purpose` claim that every verifier must remember to check (they currently do). The checkout token is
accepted **without expiry** for binding subscriptions. There is no `kid`, so the key cannot rotate without
logging everyone out. *Fix:* derive purpose-specific keys with HKDF from `JWT_SECRET`. Add
`iss`/`aud`/`typ` and verify them. Support `JWT_SECRETS=kid:key,…` with a `kid` header. Bound the checkout token's
validity (for example 7 days). *Evidence:* `server/src/index.ts:96-102, 555-561, 1311, 1346-1361`.

### P2-12 — `audit_log` is mutable; append-only triggers can be dropped by the table-owning runtime role

- The human `audit_log` has no append-only protection.
- The agent audit tables' triggers and hash chains protect against application bugs, not against a compromised
  app or DB credential. The runtime role owns the tables, so it can `DROP TRIGGER` and rewrite the chain.
- Chains are not anchored anywhere external.

*Fix:* split roles as in P1-11. Give `audit_log` the same append-only trigger. Periodically export chain heads to
an external append-only store (S3 Object Lock or a transparency log). *Evidence:* `server/src/db/schema.sql:158-171`;
`packages/agent-identity/src/schema.ts:98-110`; `server/src/db/provision.ts:85-123`.

### P2-13 — Firewall, behaviour and security-event hooks not wired to alerting; tool tickets advisory; `sweep` unscheduled

- **Blocked or anomalous agent activity raises no alert.** `createAgentIdentity` supports `onFirewallDecision`,
  `onBehaviorChange` and `onSecurityEvent`, but the server wires **none** of them. A firewall BLOCK, a behaviour
  escalation or an auto-suspension creates no Legion alert, no realtime frame and no email (except the kill-switch
  admin notice). *Fix:* map them to `outbox.insertAlertAndNotify` with `source: "agent-firewall"`.
- **Idle agents are never reassessed.** `behavior.sweep(tenantId)` is documented as "run every minute" but is not
  scheduled. Idle agents are therefore never reassessed. *Fix:* add it to `startBackgroundJobs`, iterating
  tenants that have active agents.
- **Tool and MCP enforcement is opt-in.** Tool, MCP and A2A enforcement is **ticket-based**. An agent that calls
  a tool server directly, or a tool server that never calls `/agent/v1/tools/verify`, bypasses the firewall. This
  is documented in `packages/agent-identity/README.md:1114`. *Fix:* make sure product and marketing claims match,
  and ship a reference MCP proxy or gateway that enforces tickets inline.
- **Viewers can suspend agents.** The `/agents/:id/suspend` endpoint is open to **viewers**. That is intended as a
  "big red button", but any viewer can disrupt automations. Confirm the intent and audit-alert it.

*Evidence:* `server/src/agents.ts:141-164`; `packages/agent-identity/src/index.ts:251-300`;
`packages/agent-identity/src/routes/management.ts:227`.

### P2-14 — No OpenRouter data policy; global circuit breaker trippable by one tenant; `/health` discloses provider and version

- **No data-retention guarantee.** OpenRouter requests set no provider routing or data policy (for example
  `provider: { data_collection: "deny" }`, or a zero-data-retention setting). Alert text may therefore reach
  upstream providers that retain prompts, which the privacy text does not disclose.
- **Shared circuit breaker.** The breaker is one per process across all tenants, and `malformed_response` counts
  toward it. One tenant's inputs can push the provider into odd outputs and switch AI off for everyone on that
  instance.
- **Public disclosure.** Public `/health` returns `version` and `ai_provider`, which is useful to an attacker for
  fingerprinting.

*Fix:* send an explicit provider data policy, and name the effective sub-processors in the privacy text. Keep
breaker state per provider in Redis and don't count content-caused failures. Reduce public `/health` to
`{status}` and move details to the token-protected endpoints. *Evidence:* `server/src/ai.ts:181-197, 270-283`;
`server/src/index.ts:344-363`.

### P2-15 — Mock provider `/security-events/sync` creates fake high-severity alerts (and emails) in production

Any admin can insert "Mock provider: suspicious authentication burst" alerts. These are `high` severity, so they
trigger alert emails, and they are mixed into real SOC data and statistics. *Fix:* disable the endpoint unless
`SEED_DEMO_DATA`/development mode is on, or tag such alerts clearly as test data and exclude them from
notifications. *Evidence:* `server/src/index.ts:1484-1499`.

### P2-16 — `sent` alert emails, audit and decision logs grow forever; no retention jobs

Only delivered `realtime_alert` rows are pruned. `alert_email` rows, with recipient and full rendered content,
stay forever, as do `audit_log`, `principal_audit_log`, `firewall_decisions`, `alerts` and `assets`.
`mfa_used_counters` is pruned only on that user's next successful login. *Fix:* add a single housekeeping worker
(advisory-locked) with per-table retention. Consider monthly partitioning for `alerts` and the audit tables so
deletion becomes `DROP PARTITION`. *Evidence:* `server/src/outbox.ts:368-373, 410-413`; `server/src/mfa.ts:139-143`.

### P2-17 — Two divergent lockfiles; runtime depends on a devDependency; build artefacts in the archive

- **Divergent lockfiles.** The root `package-lock.json` resolves `next@16.3.6`, while `frontend/package-lock.json`
  resolves `next@16.3.0`, so the dashboard build depends on which install ran. Keep one workspace lockfile.
- **Runtime needs a dev tool.** `npm start` needs `concurrently` from devDependencies (P1-9).
- **Unreviewed code at install.** `postinstall` builds the agent package, so installs run arbitrary build steps.
- **Stray artefacts.** `frontend/tsconfig.tsbuildinfo` and `integrations/__pycache__` are in the archive.
- **Dependency hygiene.** Dependabot and `npm audit` exist in CI, but CI isn't running (P0-1).

*Fix:* single lockfile, `npm ci --omit=dev` for production, and an SBOM (CycloneDX) plus provenance per release.

### P2-18 — All secrets in plaintext `.env` (DB password twice); dev key derived from JWT stays decrypt-capable

- **Everything in one file.** `server/.env` holds `JWT_SECRET`, `LEGION_ENCRYPTION_KEYS`, the DB URL *and* a
  duplicate `__DB_PASSWORD`, plus Paddle, SMTP and AI keys. It is mode 600 on one host, with no secret manager or
  rotation tooling for most of them.
- **A leaked JWT can unlock secrets.** The keyring always keeps a decrypt-only `dev` key derived from
  `JWT_SECRET`. A leaked JWT secret plus a DB copy can therefore decrypt any secret still sealed under `dev`.

*Fix:* load from systemd credentials (`LoadCredential=`), Vault or the cloud secret manager. Drop
`__DB_PASSWORD`. Once `npm run secrets -- status` shows no `dev`-sealed rows, stop adding the `dev` key.
*Evidence:* `server/scripts/setup.mjs:303-344`; `server/src/secret-box.ts:48-50, 63`.

### P2-19 — Node `keepAliveTimeout` (5 s) is shorter than nginx upstream keep-alive → sporadic 502s

nginx keeps upstream connections alive (`keepalive 16`), and Node closes idle sockets after 5 s. The race
produces intermittent 502s under light load. *Fix:* set `httpServer.keepAliveTimeout = 65_000` and
`headersTimeout = 66_000` (currently 30 s), or set `keepalive_timeout 4s` in the nginx upstream. *Evidence:*
`server/src/index.ts:1736-1737`; `deploy/nginx.conf`.

---

## 4. Areas reviewed without significant findings

These controls were read end-to-end and hold up, beyond the items above:

- **Password reset, invite and verify:** hashed tokens, single-use consuming `UPDATE`, expiry, `token_version`
  bump, and invitation preview by `POST` (the token stays out of URLs and logs).
- **First-run setup (self-hosted):** a console token, advisory lock and a single transaction prevent the
  "first visitor becomes admin" race.
- **RBAC on core routes:** viewer < analyst < admin enforced per route. Role changes bump `token_version` and
  revoke sessions and sockets. The last-admin guard exists (see P2-4 for the race).
- **Agent permissions:** tier-3 powers (users, credentials, settings) can never be granted to machines. Effective
  permissions are the intersection with the owner's current role. Delegations are bounded to 7 days and to the
  granter's role.
- **Agent firewall:** fails closed when policy, lookups or the decision log are unavailable. Enforce mode is the
  default. Machines are confined to `/agent/v1`.
- **Copilot / Oracle prompt handling:** untrusted fence with a random boundary, invisible-character stripping,
  identifier shape checks, output sanitising, and no tools or function calling.
- **Webhook credential lifecycle:** create, rotate (with overlap) and revoke, capped at 5 active per tenant,
  shown once, `no-store`.
- **CORS / Origin / WebSocket hijacking:** exact allow-lists with no wildcard or `null`. WebSocket Origin is
  required, tokens are cookie-only (no `?token=`), and sockets are revalidated every 20 s and expire with the
  access token.
- **SQL injection:** every query I read is parameterised. Dynamic column lists are whitelisted
  (`USER_COLUMNS`).
- **Email HTML:** all interpolations are escaped. Message-ID is stable across outbox retries.

---

## 5. Prioritised remediation roadmap

Effort: **S** ≤ 2 days · **M** ≤ 1–2 weeks · **L** > 2 weeks (one engineer).

### Phase 0 — before any production traffic (week 1)

| # | Item | Effort | Depends on |
|---|---|---|---|
| 1 | **P0-1** Commit the source, turn on CI with a required release gate, delete or rebuild the Docker path | S–M | — |
| 2 | **P1-14** Real dummy bcrypt hash + latency test | S | 1 |
| 3 | **P1-9** Split systemd units, `NODE_ENV=production`, `node` directly, `Restart=always` | S | 1 |
| 4 | **P1-3** Failed-auth limiter on webhook; cheap `/livez`; nginx `limit_req` | S | — |
| 5 | **P1-4** Server-side price allow-list + server-created checkout (**before live Paddle**) | M | — |
| 6 | **P2-15** Disable the mock `/security-events/sync` outside dev | S | — |
| 7 | **P2-9 (HSTS part)** HSTS in nginx | S | — |

### Phase 1 — before GA / paid SaaS (weeks 2–5)

| # | Item | Effort | Depends on |
|---|---|---|---|
| 8 | **P1-2** Versioned migrations as a deploy step, lock-safe DDL, owner/runtime role split | M | 1 |
| 9 | **P1-1** Durable sensor delivery (spool + drain), event truncation, ingest queue | M | 8 |
| 10 | **P1-10** pino + request IDs, Prometheus metrics, error tracking, alert rules | M | 3 |
| 11 | **P1-5** Subscriptions keyed by Paddle subscription ID; aggregate access state | M | 8, 5 |
| 12 | **P1-6** Subscription gate over the agent-identity surface (kill switch always allowed) | S | — |
| 13 | **P1-7** Durable per-tenant and per-plan AI budgets + usage table | M | 5, 8 |
| 14 | **P1-8** Refresh grace window + cross-tab lock | S–M | 8 |
| 15 | **P1-13** PITR / managed Postgres, mandatory off-site copy + restore test, keys in a secret manager | M | — |
| 16 | **P1-12** Retention jobs, tenant export and delete, audit-chain redesign, align legal text and backup retention | L | 8, 11 |

### Phase 2 — scale and hardening (months 2–3)

| # | Item | Effort | Depends on |
|---|---|---|---|
| 17 | **P1-11** RLS (`FORCE`) with per-request tenant GUC, cross-tenant worker role, agent-table foreign keys | L | 8 |
| 18 | **P2-7 / P2-6** Per-request caching, pool sizing + pgbouncer, ingest throughput benchmark | M | 9, 10 |
| 19 | **P2-8** Realtime: ID-only frames, Redis auth + TLS, socket caps, ping/pong, back-pressure | M | 10 |
| 20 | **P2-1 / P2-2 / P2-3 / P2-4** Auth hardening (MFA policy and notifications, absolute session life, enumeration, locking) | M | 14 |
| 21 | **P2-9 (CSP) / P2-10 / P2-11 / P2-12 / P2-18** Nonce CSP, config schema, JWT key rotation, audit anchoring, secret manager | M–L | 8, 17 |
| 22 | **P2-13 / P2-14 / P2-16 / P2-17 / P2-19** Agent alert hooks + sweep, AI data policy, retention worker, single lockfile + SBOM, keep-alive | M | 10, 16 |

**Critical path:** P0-1 → P1-2 (migrations) → {P1-1, P1-5, P1-12, P1-11}. The migration framework is the
foundation for almost every data-layer fix, so start it as soon as the source is in the repository.

**Exit criteria for "production-ready":**

- CI green and required on `main`.
- Zero open P0/P1 findings.
- A restore drill from an off-site copy completed within the stated RTO.
- A 1-hour Legion outage replayed from Wazuh with zero lost alerts.
- Billing sandbox tests covering foreign prices, discounts and multiple subscriptions.
- A dashboard and alerts for ingestion, outbox, DB pool and backups.
