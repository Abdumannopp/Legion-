# Legion — audit fixes

**Date:** 2026-08-20
**Context:** a SaaS for the global market. The three "broken chains" and the security gaps found in the audit were fixed.

State at the time: `tsc` clean (server + frontend), **96 tests pass on real Postgres**, `next build` succeeds, `npm audit` — 0 vulnerabilities.

> **2.1 (2026-08-21):** backup, Redis rate limiting, MFA and refresh tokens added — see section 8.

---

## 1. The team chain is connected — RBAC is now live

Previously there was no `POST /users` at all: every customer was stuck with one
user forever, and the `analyst`/`viewer` roles were never created.

**New endpoints**

| Endpoint | Who | Purpose |
|---|---|---|
| `POST /users/invite` | admin | Creates and sends an invitation by email + role |
| `POST /users/:id/resend-invite` | admin | Resends with a new token (the old link dies) |
| `POST /auth/accept-invite` | public | Sets a password, joins the **existing** tenant |
| `GET /auth/invite/:token` | public | Preview for the accept page |
| `DELETE /users/:id` | admin | **Deactivates** the account (does not delete it) |
| `POST /auth/change-password` | anyone | The signed-in user changes their password |

**Key decisions**

- `/auth/accept-invite` is a completely separate path from `/auth/register`. Register always creates a **new tenant**; an invitation joins an **existing** one. Mixing them up would have the invitee create their own workspace.
- Deactivate, do not delete: audit-log entries refer to the user and must resolve to a real person. `status: "disabled"` + `token_version += 1` → sessions end immediately.
- The "at least one admin" rule now counts **active** admins — a deactivated admin does not count (previously a hole).
- Email is the sign-in identifier, so it is unique across all tenants.

**Frontend:** the `/accept-invite` page; in Settings → Team an invitation form, role selection, resend and deactivate buttons, status labels.

---

## 2. The money chain is connected — a subscription now really limits access

Previously the Paddle integration only **displayed** the subscription. A cancelled customer kept unlimited access.

**New `accessState(tenantId)` logic**

| State | Result |
|---|---|
| `active` or `trialing` subscription | `ok` — full access |
| No subscription, trial still running | `ok` |
| No subscription, trial ended | `blocked` → `402` |
| `past_due` | `readonly` — `GET` allowed, writes `402` |
| `paused` / `canceled` | `blocked` → `402` |

**Deliberate choices**

- **`/auth/*` and `/billing/*` are never blocked.** A customer who cannot sign in or open the billing portal can never pay again.
- **The Wazuh webhook is never blocked.** Dropping a customer's telemetry because a payment is late leaves a hole in their security history that can never be filled. Billing limits the UI, not event recording.
- `past_due` is not darkness but **read-only**. Hiding a live incident over an unpaid invoice is a bad trade.
- `Tenant.trial_ends_at` is a separate field — sales can extend a trial without touching code.

**Frontend:** the `AccessBanner` component (dashboard + settings). In the normal state it **shows nothing** — a banner that is always there goes unread. It appears 5 days before the trial ends, and in the `readonly` and `blocked` states.

---

## 3. The AI chain is connected — Copilot now reads the question

Previously `/copilot/chat` parsed `body.message` and **never used it** — it returned the same template answer whatever was asked.

New `server/src/ai.ts`:

- Copilot sends the user's question, the conversation history (last 10 messages) and context built from the tenant's last 30 alerts to the model.
- Oracle (`/alerts/:id/explain`) uses the same layer.
- **Prompt-injection protection:** alert text (`full_log`, host names) comes from the customer's environment — an attacker who can cause a log line can put words there. Alert data is passed inside a fence, and the system prompt declares it untrusted data.
- Without a key, or if the model fails, the old deterministic answer remains as a **fallback**. An AI outage does not take down the dashboard (20 s timeout).
- The response includes `source: "ai" | "local"`.

---

## 4. Assets are now a live inventory

The Wazuh webhook created alerts but not assets — the Assets page showed demo data forever.

Now every event upserts the asset by `agent.name`: `last_seen`, `ip_address` and `os` are updated.

**Risk calculation:** it is not "pinned" to the worst severity ever seen — it is recalculated over the last **7-day window**. Otherwise one critical alert would leave an asset red forever. Now a quiet asset comes down by itself.

---

## 5. Security fixes (audit items 1–7)

| # | Problem | Fix |
|---|---|---|
| 1 | A demo admin in production | `SEED_DEMO_DATA` forced to `false` in production. Production starts with an empty database. |
| — | Weak production configuration | The server **refuses to start** without `JWT_SECRET` (32+), `COOKIE_SECURE=true`, an `https://` FRONTEND_URL and `SMTP_HOST`, and lists the reasons. |
| 2 | `/auth/register` race condition | The hash is now computed **before** the check; no `await` between check and write. Test: of 3 parallel requests only 1 returns 201. |
| 4 | WS `?token=` fallback | Removed entirely — cookie only. JWTs no longer end up in proxy/access logs. |
| 5 | Reset token compared with `===` | `timingSafeEqual` (`safeEqual` helper). Applied to invite tokens too. |
| 6 | Demo email on the sign-in form | Removed. |
| — | Deactivated accounts | The `auth` middleware now returns 401 when `status !== "active"` (WS too). |

---

## 6. PostgreSQL migration (2.0)

The JSON store was removed entirely. **Postgres is the single source of truth** — no in-memory copy is kept.

This is deliberate and the whole point of the migration: with an in-memory copy, a second instance shows stale data and a write on one pod is invisible on another — which makes running more than one instance pointless.

### New structure

```
server/src/db/pool.ts      pg Pool, query/transaction helpers, migrate()
server/src/db/schema.sql   6 tables, indexes, CHECK constraints
server/src/store.ts        Repository — all SQL lives only here
server/src/seed.ts         Demo data (never in production)
server/src/scripts/        JSON -> Postgres import
```

The schema is applied idempotently on every start. Instances starting at the same time are serialised with an **advisory lock** — otherwise parallel `CREATE INDEX` statements deadlock each other and break a deploy that updates several pods at once.

### Guarantees moved into the database

Rules that used to live in application code (and were therefore unreliable) are now database constraints:

| Guarantee | Before | Now |
|---|---|---|
| Unique email | `users.some(...)` check | `UNIQUE INDEX ON lower(email)` |
| Duplicate alert | `alerts.some(...)` check | `ON CONFLICT (tenant_id, id) DO NOTHING` |
| Asset upsert | read-then-write | one `INSERT ... ON CONFLICT` |
| Paddle ordering | `if (stale) return` in the app | `WHERE ... EXCLUDED.last_event_at >= ...` |
| Tenant+admin atomicity | none (orphan tenants left behind) | one transaction |
| `token_version` increment | read-then-write | `SET token_version = token_version + 1` |

**Confirmed under real load:**

- 200 parallel Wazuh events → 0.96 seconds (~209/s), all written correctly
- The same event 30 times in parallel → **exactly 1** alert
- 20 parallel sign-ups with the same email → **1 user, 1 tenant** (no orphan tenant)

### Security improvement: alert IDs are now scoped to the tenant

The primary key of `alerts` is `(tenant_id, id)`, not a global `id`.

Previously a user of one tenant who sent `POST /alerts` with an ID existing in another tenant got "Alert ID already exists" — revealing that the alert ID existed in another workspace. That is no longer possible, and two tenants can use the same ID freely.

### Other changes

- `/health` now queries the database. A health check that does not touch the database would keep saying "ok" while every request returned 500.
- Sign-in runs a bcrypt comparison for unknown emails too — response time does not reveal whether an email exists.
- Token lookup (`invite_token`, `reset_token`) is compared in constant time in the application, not in SQL: `WHERE invite_token = $1` would leak the match position through query timing.
- The artificial 20,000-row limit on the audit log was removed — Postgres does not need it.
- Statistics are computed with one aggregate query (previously every alert was loaded into memory).
- On `SIGTERM`/`SIGINT` connections are drained, with a 10-second forced timeout.

### Moving the data

```bash
npm run import:json -w server -- ./data/legion.json
```

Idempotent; does not modify the JSON file. Fields missing in the old schema are filled in: `status='active'`, `token_version` kept, and the tenant gets a **new** trial window (counting from the creation date would have blocked paying customers on migration).

### Developer-experience change — be aware

"PostgreSQL is not required to run locally" in the README is no longer true. Running locally needs Postgres (`docker compose up postgres -d`). That is the right trade for a SaaS: customers use a browser; Postgres exists only in your infrastructure.

---

## 7. Writing to disk — the old JSON store (before 2.0)

**Problem:** every mutation serialised the whole database to JSON and rewrote it. Alert ingestion mutates twice (alert + audit). In a Wazuh burst that meant hundreds of full rewrites per second, and the queue grew faster than it drained.

**What was done:** writes are merged inside a **coalescing window** (`PERSIST_FLUSH_MS`, default 200 ms). All `persist()` calls in one window share a single write. Durability is unchanged — `await persist()` still resolves after the bytes are on disk, through the same atomic temp+rename. On `SIGTERM`/`SIGINT` a pending write is flushed.

In a burst, 1000 alerts = about 5 writes instead of 2000 full rewrites.

**Why a full SQLite migration was not done.** Endpoints mutated data directly (`alert.status = body.status`). A real SQLite migration means rewriting about 30 write sites. Rushing that is exactly how a tenant-isolation bug gets into a security product. The tests cover behaviour, not the storage layer.

**Next step (separate work, since done in 2.0):** writes were still `O(database size)`. The right fix is a real database — **Postgres** for a multi-instance SaaS, since SQLite is limited to one process.

---

## New configuration

```env
NODE_ENV=development          # strict checks are enabled in production
SEED_DEMO_DATA=true           # forced to false in production
TRIAL_DAYS=14                 # trial length for a new tenant
INVITE_DAYS=7                 # how long an invitation link is valid
PERSIST_FLUSH_MS=200          # write-coalescing window
```

Required in production: `JWT_SECRET` (32+ characters), `COOKIE_SECURE=true`, `FRONTEND_URL=https://...`, `SMTP_HOST`.

---

## Tests

`npm test` — 47 tests, ~4 seconds at the time. Areas covered:

- **Tenant isolation** — alerts, users, status changes, attempts to change another tenant's role
- **RBAC** — viewer/analyst/admin boundaries
- **`token_version` revocation** — a role change and deactivation kill old tokens
- **Invitation flow** — create, preview, accept, reuse, expiry, resend, no sign-in before acceptance
- **Deactivation guards** — oneself, the last admin
- **Subscription gate** — trial, active, canceled, past_due read-only, exempt paths
- **Webhook** — signature, unknown tenant, dedup, asset creation, accepted even for a blocked tenant
- **Sign-up** — duplicates, race condition, no email enumeration, password change
- **Write coalescing**

---

## 8. Production readiness (2.1)

Four gaps closed. Each was measured in a real environment, not assumed.

### 8.1 Backup and disaster recovery

Once Postgres is the single source of truth, one bad day without backups = all customer data.

```
ops/backup.sh          dump + readability check + prune old copies
ops/verify-backup.sh   restore into a temporary database and VERIFY the data
ops/restore.sh         restore over the existing database (--single-transaction)
BACKUP.md              runbook: RPO/RTO, cron, off-site, disaster procedure
```

`verify-backup.sh` does not just say "restored": it checks that the expected tables
exist, that tenants are not empty and that there are no orphan users. **Tested:**
40 alerts created → backup → `DROP SCHEMA public CASCADE` → restore → sign-in and
alerts worked without restarting the server.

The script proved its worth straight away — it detected that the `refresh_tokens`
table was missing from the schema and returned an error saying "do not trust this backup".

### 8.2 Rate limiting across instances

`express-rate-limit`'s default store counts in memory. The Postgres migration had
opened horizontal scaling, but the limiter still worked as if there were one instance.

**Measured (3 instances, limit 10/minute, 36 attempts):**

| | Allowed through |
|---|---|
| Without Redis | **30** — three times the limit |
| With Redis | **10** — exactly the limit |

The Wazuh webhook, `/health` and the Paddle webhook are **excluded** from the
general limit: a busy SOC exceeds any limit comfortable for a dashboard, and
throttling telemetry leaves a hole in the customer's security history.

If Redis goes down, `passOnStoreError` lets requests through (protection weakens,
but the platform stays up) and the error is logged.

**Two bugs found along the way:**

1. **Seed race.** When three instances started on an empty database at once, all
   tried to write demo data; the losers **crashed** on a unique constraint. With
   replicas, every new deploy put pods into a restart loop. Fixed with an advisory
   lock + re-checking inside the lock.

2. **RedisStore created before connecting.** `store.init()` loads a Lua script;
   with the client not yet connected it failed silently and the limiter **let
   everything through**, while Redis logged "connected". Monitoring green — no
   protection. Fixed with a top-level `await connect()` at module load.

Neither the typecheck nor the 53 tests caught them — only a real multi-instance test did.

### 8.3 MFA (TOTP)

When Legion saw an alert it advised `"Reset affected credentials and enforce MFA"`,
yet did not have MFA itself.

| Endpoint | Purpose |
|---|---|
| `POST /auth/mfa/setup` | Creates a secret, returns an `otpauth://` URI |
| `POST /auth/mfa/enable` | Confirms a code, issues 10 recovery codes |
| `POST /auth/mfa/verify` | The **second** step of sign-in |
| `POST /auth/mfa/disable` | Requires the password **and** a code |
| `POST /auth/mfa/recovery-codes` | A new set (the old one dies) |

Decisions:

- **MFA is not enabled until a code is confirmed** — so a badly scanned QR code
  cannot lock the user out.
- **Replay protection:** every accepted TOTP counter is written to
  `mfa_used_counters`. A code is valid for 30 seconds; a code seen in transit could
  otherwise be reused within that window.
- **Recovery codes are stored only as bcrypt hashes** and shown once.
- **A challenge token is not a session.** It is signed with the same key and the
  same claims as a session token — `authenticate` now refuses any token with a
  `purpose` claim. Without that, anyone who noticed could bypass MFA.

### 8.4 Refresh tokens

The access token lasted 1 hour with no refresh: a SOC analyst was signed out every
hour during a shift. Making it longer would be worse — a stateless JWT cannot be revoked.

Now: a short access token (15 min) + a long refresh token (30 days) in the
`refresh_tokens` table, **rotated** on every use.

- **Theft detection:** if an already-rotated token is presented again, two parties
  hold it and it is impossible to tell which is genuine — the whole family is
  revoked. This turns silent ongoing access into **one visible sign-out**.
- **Only a SHA-256 hash is stored** (not bcrypt: the token is 256 random bits, and
  refresh runs on every page load).
- **Two tabs at once:** with `FOR UPDATE`, exactly one rotates.
- **One shared refresh in the frontend:** the dashboard sends 6 requests per page;
  if each refreshed separately, every one but the winner would count as a replay and
  sign the user out exactly when the session is valid.
- A password, role or deactivation change revokes **all sessions**.
- Expired rows are cleaned up every 6 hours (otherwise the table grows by one row per refresh).

### 8.5 Not yet at the time

- **PITR** — with a daily dump, RPO is 24 hours. Enable it on a managed Postgres.
- **Backup encryption and off-site copies** — documented, not in the script (later done — see [RECOVERY.md](RECOVERY.md)).
- **Enforcing MFA per tenant** — at the time each user enabled it themselves.
- **SSO/SAML** — required by large corporate buyers.
- **Retention and observability** — see section 7.
