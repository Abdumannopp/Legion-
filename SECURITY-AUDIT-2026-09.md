# Legion — production premortem audit (2026-09)

**Branch:** `claude/legion-security-audit-44rtuh`
**Method:** assume Legion has already failed in production; find the realistic
causes, prove them from files where possible, fix what can be fixed safely.

---

## 0. What was actually audited — read this first

The request referred to `Legion.zip`. The repository contains **only the 23
top-level files** of that project (one commit, "Add files via upload"). No
zip file exists in the repository, in the account's Google Drive, or in any
other repository the account can reach.

**Missing — and therefore not audited:**

| Directory | What it holds (per the project's own docs) |
|---|---|
| `server/` | Express/TypeScript API: auth, MFA, webhooks, WebSocket, Redis, AI, email, DB schema, 134 tests |
| `frontend/` | Next.js dashboard |
| `integrations/` | Wazuh `custom-legion` / `custom-legion.py` |
| `ops/` | `backup.sh`, `verify-backup.sh`, `restore.sh` |
| `deploy/` | `nginx.conf` (the HTTPS reverse proxy) |
| `monitoring/` | `prometheus.yml` (referenced by `docker-compose.monitoring.yml`) |
| `scripts/` | `try-local.mjs` (`npm run try`) |

**Present and audited:** `docker-compose*.yml`, `install.sh`,
`start-legion.ps1`, `package.json`, `package-lock.json` (it records every
resolved dependency of `server/` and `frontend/`), and the 14 documentation
files, including the project's own earlier audits and design records.

**Evidence labels used below**

| Label | Meaning |
|---|---|
| **Verified** | Proven from a file in this repository, reproduced, or measured |
| **Documented** | The project's own docs state that the code behaves this way; the code itself was not available to confirm |
| **Potential** | Plausible given the architecture; not confirmable without the code |
| **Not tested / Blocked** | Could not be exercised here, with the reason |

---

## 1. Architecture (as documented by the project)

```
Wazuh agent → Wazuh manager → integratord → custom-legion.py
   → POST /security-events/webhook   (headers: x-tenant-id, x-security-event-secret)
      → Express API ──► Postgres (single source of truth: tenants, users, alerts,
      │                            assets, audit log, refresh_tokens, mfa_used_counters)
      ├─► email (nodemailer/SMTP, severity ≥ ALERT_EMAIL_MIN_SEVERITY)
      ├─► Redis pub/sub ─► every API instance ─► WebSocket (cookie auth) ─► browser
      └─► AI on demand (Oracle / Copilot → OpenRouter or Groq, else local fallback)

Browser ──► Next.js dashboard (port 3000) ──► API directly at NEXT_PUBLIC_API_URL (port 8000)
Redis: rate-limit counters + realtime fan-out, no persistence
Auth: bcrypt passwords; 15-min access JWT + 30-day rotating refresh token (SHA-256
      stored, reuse → family revoked); optional TOTP MFA; invitations; password reset
Deploy: docker compose (postgres, redis, backend, frontend) or plain Node on Linux/Windows
```

- **Ingestion is synchronous.** DB write, e-mail and asset upsert happen
  inside the webhook HTTP request; there is no queue (ADR-002, "Bugun kodda").
- **Dedup** is `ON CONFLICT (tenant_id, id) DO NOTHING`, answered with
  `202 skipped, duplicate` (CHANGELOG-AUDIT §6, WAZUH.md).
- **Tenancy** is one tenant per user; the email address is globally unique
  (ADR-001).

---

## 2. Risk register

Severity is the damage if the risk happens; likelihood is how likely it is
to happen in a real deployment.

| # | Risk | Sev. | Likelihood | Impact | Evidence | Status | Fix |
|---|---|---|---|---|---|---|---|
| R1 | Next.js 16.3.0: unauthenticated RCE on Windows hosts + AVIF image-optimizer RCE | **Critical** | High (public advisories; Windows is a supported host) | Full server takeover | Verified (`npm audit`) | **Fixed** | Lockfile → 16.3.6 |
| R2 | Webhook credential is a static `HMAC(global_secret, tenant_id)`: covers no body, no timestamp, one secret for all tenants | **Critical** | Medium | Forged/replayed alerts for any tenant; alert flooding; attacker text reaching the AI | Documented (INSTALL §5, WAZUH.md, ADR-003) | **Open — needs server code** | §5.1 |
| R3 | Alert stored but operator never notified: e-mail/realtime run in-request with no retry; a redelivery is "duplicate" and skipped | **Critical** | Medium | Silent missed incident | Documented (ADR-002, CHANGELOG §6, WAZUH.md) | **Open — needs server code** | §5.2 |
| R4 | Wazuh `integratord` does not retry; alerts that fire while Legion is down (upgrade, restart, DB outage) never arrive | **High** | High (every upgrade is an outage window) | Permanent gaps in security history | Potential (script not uploaded) | **Open** | Spool + retry in `custom-legion.py`; §5.2 |
| R5 | Dashboard/API ports published on `0.0.0.0`; Docker bypasses ufw/firewalld; fresh install lets the first visitor become admin | **High** | High on any public VPS | Stranger claims admin of a new install; unauthenticated Prometheus | Verified (compose) | **Fixed** | Loopback by default, explicit opt-in |
| R6 | Re-running `install.sh` with `JWT_SECRET` missing from `.env` regenerates the DB password and overwrites all settings | **High** | Medium (hand-edited `.env`) | Legion locked out of its own database; SMTP/URL settings wiped | **Reproduced** | **Fixed** | Never rewrite `.env`; refuse |
| R7 | `.env` lost while the DB volume exists → new random password → lockout | **High** | Medium | Same as R6 | Verified (logic + real-volume test) | **Fixed** | Refuse, explain restore |
| R8 | Documented backup (`ops/backup.sh` via `DATABASE_URL`) cannot reach Postgres in the Docker install (port not published) | **High** | High for Docker installs | "Backups" that never ran | Potential (script not uploaded; compose verified) | **Mitigated** | `ops/docker-backup.sh` + restore, tested |
| R9 | Upgrades apply schema changes automatically with no backup first | **High** | Medium | Unrecoverable failed migration | Verified (`install.sh`) | **Fixed** | Pre-upgrade backup; abort if it fails |
| R10 | Password-reset / invitation tokens appear to be stored in plaintext and matched by scanning in app code | **High** | Low–Medium (needs DB/backup read) | Account takeover from a leaked DB or unencrypted backup | Documented (CHANGELOG §6 token lookup rationale) | **Open — needs server code** | §5.3 |
| R11 | nodemailer 9.0.5: recipient-domain validation bypasses (mail to attacker domain), address-parser DoS | **High** | Low–Medium | Reset/invite links to the wrong domain; e-mail DoS | Verified (`npm audit`) | **Fixed** | 9.1.1 |
| R12 | Lockfile only contained Linux-x64-glibc native binaries for Next.js and sharp | **High** | High on Windows/ARM/Alpine | Install/build fails on a supported platform | Verified (lockfile) | **Fixed** | Regenerated lockfile has all platforms |
| R13 | Postgres/Redis images never refreshed by the upgrade path | **Medium** | High over time | Unpatched database indefinitely | Verified (`install.sh`) | **Fixed** | `compose pull` + `build --pull` |
| R14 | Redis pub/sub is fire-and-forget; no documented resync after WebSocket reconnect or Redis outage | **High** | Medium | Live dashboard silently misses alerts | Potential | **Open — needs server/frontend code** | §5.4 |
| R15 | Rate limiter fails open when Redis is down; `trust proxy` setting unknown | **Medium** | Medium | Brute-force protection disappears / all users share the proxy IP | Documented (CHANGELOG §8.2) / Potential | **Open** | §5.5 |
| R16 | WebSocket uses cookie auth; Origin validation not documented | **Medium** | Low–Medium (depends on SameSite) | Cross-site WebSocket hijacking of the alert stream | Potential | **Open — verify in code** | §5.5 |
| R17 | TOTP secret protection at rest not documented (recovery codes are hashed) | **Medium** | Low | MFA bypass from a DB/backup leak | Unknown | **Open — verify in code** | §5.3 |
| R18 | First-admin race safe only inside one process ("no await between check and write") | **Medium** | Low | Two administrators/tenants on a multi-instance first boot | Documented | **Open** | §5.6 |
| R19 | `/health` checks the DB only: not Redis, SMTP, or undelivered notifications | **Medium** | High | Green health while alerts go undelivered | Documented (health output) | **Open** | §5.2 |
| R20 | Forged or crafted events reach the AI prompt; defence is prompt wording only | **Medium** | Medium (easy with R2) | Misleading AI advice to operators | Documented (CHANGELOG §3) | **Open** | §5.7 |
| R21 | No CSP/HSTS/frame-ancestors on the dashboard | **Medium** | Medium | XSS/clickjacking impact larger than needed | Documented (ADR-009) | **Open** | ADR-009 plan |
| R22 | No CI; docs claimed "npm audit: 0 vulnerabilities" while a critical RCE was in the lockfile | **Medium** | — (already happened) | Security claims go stale unnoticed | Verified | **Fixed** | CI + Dependabot |
| R23 | Docker logs never rotated | **Medium** | High over months | Disk full → Postgres stops → ingestion stops | Verified | **Fixed** | 10 MB × 5 per service |
| R24 | Wrong URL combinations (remote dashboard + `localhost` API, https + http API) are only discovered in the browser | **Medium** | High on first real deploy | Dashboard loads with no data | Verified (baked-in `NEXT_PUBLIC_API_URL`) | **Fixed (Docker path)** | Installer validation |
| R25 | `WAZUH.md` tells operators to read the tenant ID from a JSON file removed in 2.0; restart with `npm run dev` | **Medium** | High | Wazuh integration cannot be completed as written | Verified | **Fixed** | Docs |
| R26 | `WINDOWS-NODE.md` advertises `admin@legion.demo / legion123` and JSON storage | **Medium** | Medium | Operators expect/create a known credential | Verified | **Fixed** | Docs |
| R27 | Backups unencrypted and not copied off-server automatically; RPO 24 h | **Medium** | Medium | Data loss with the server; leaked dumps expose everything (see R10) | Documented (BACKUP.md) | **Open** | Encrypt + ship off-site |
| R28 | Legion has never been tested against a real Wazuh manager | **High** | — | The core product path is unproven | Documented (AUDIT-2, SINOV, MIJOZGA) | **Open — process** | §6 |
| R29 | `docker-compose.monitoring.yml` mounts `monitoring/prometheus.yml`, which is not in the repository | **Low** | High if used | Monitoring stack will not start | Verified (for this repo) | **Open** | Commit the file |
| R30 | Frontend started before the API was healthy | **Low** | Medium | Error pages on first load after restart | Verified | **Fixed** | `service_healthy` |
| R31 | Installer's readiness check ignored `API_PORT` | **Low** | Low | False "did not become ready" | Verified | **Fixed** | Uses Docker's healthcheck |

---

## 3. Critical findings, in plain English

### R1 — A critical, publicly known hole in the dashboard framework

- **Technical:** `package-lock.json` pinned `next@16.3.0`, affected by
  GHSA-p293-qw3h-jr36 (unauthenticated remote code execution on
  Windows-hosted servers) and GHSA-2xp9-vwfh-vxw4 (RCE via the image-optimization API
  with AVIF files).
- **Plain English:** someone on the internet could run their own programs on
  the Legion server without logging in. Legion ships a Windows launcher
  (`start-legion.ps1`), so the Windows variant applies.
- **Impact:** total compromise of the security console and every tenant's data.
- **Action (done):** lockfile updated to `next@16.3.6` along with the other
  five advisories; `npm audit` now reports 0; CI fails on any new high or
  critical advisory; Dependabot proposes updates weekly.

### R2 — The Wazuh webhook password never changes and does not protect the message

- **Technical:** per INSTALL.md §5 and WAZUH.md,
  `x-security-event-secret = HMAC-SHA256(SECURITY_EVENT_WEBHOOK_SECRET, tenant_id)`.
  The value is constant per tenant, covers neither the body nor a timestamp,
  and every tenant's value comes from one server-wide secret. The sample
  `hook_url` is plain `http://`.
- **Plain English:** it's a fixed password sent with every message, often
  unencrypted. Anyone who sees it once can send Legion fake alerts, or resend
  old ones, whenever they like. Whoever knows the one master secret can do
  this for every customer.
- **Impact:** attackers can bury a real intrusion under fake alarms, or feed
  crafted text to the AI assistant (R20).
- **Action:** needs the server code — design in §5.1. Done here: API bound
  to loopback so the header can't cross the network in plain HTTP by
  default; limitation documented in WAZUH.md and INSTALL.md.

### R3 / R4 — "The alert was received, but nobody found out"

- **Technical:** ingestion writes the alert, then sends e-mail and realtime
  events in the same request, with no queue or retry (ADR-002). A redelivery
  of the same event returns `202 skipped, duplicate`, so side effects that
  failed the first time are never retried. Wazuh's integratord runs the
  script once per alert and does not retry.
- **Plain English:** if the mail server hiccups, Redis restarts, or Legion
  is mid-upgrade at the wrong moment, an alert can be saved with nobody told,
  or not saved at all, and nothing tries again.
- **Impact:** the exact failure a security product exists to prevent.
- **Action:** needs server code (transactional outbox, §5.2) and a spooling
  Wazuh script. Done here: upgrades are now shorter and safer (backup first,
  health-gated startup), but the gap is not closed.

### R5 — A fresh server could be claimed by a stranger

- **Technical:** `docker-compose.yml` published 8000 and 3000 on all
  interfaces. Docker inserts its own iptables rules, so `ufw deny 3000` has no
  effect. Registration is open until the first account exists.
- **Plain English:** between running the installer and creating your admin
  account, anyone who finds the server's IP can create the admin account
  first and own the installation. The firewall you think is protecting it
  isn't.
- **Action (done):** ports now listen on `127.0.0.1` unless the operator
  explicitly sets `LEGION_BIND_ADDRESS=0.0.0.0`. The installer refuses
  configurations that can't work with that, and explains the choice.
  Prometheus is loopback-only too. A test fails if any port is re-exposed.

### R6 / R7 / R8 / R9 — Ways to lose the database

- **Technical:** the original `install.sh` treated "no `JWT_SECRET` in
  `.env`" as a new install, generated a new `POSTGRES_PASSWORD`, and
  overwrote `.env`. Reproduced: a `.env` holding the real password,
  an https `FRONTEND_URL` and an SMTP host came back with a random password,
  `http://localhost:3000`, and an empty SMTP host. Upgrades ran migrations with
  no backup. The documented backup script connects from the host, but Docker
  doesn't publish Postgres.
- **Plain English:** a small mistake in one settings file could lock Legion
  out of all its data, and the backup you thought was running probably
  wasn't.
- **Action (done):** the installer never rewrites an existing `.env` and
  refuses when secrets are missing or a database already exists without its
  password. It backs up before every upgrade and stops if the backup fails.
  New `ops/docker-backup.sh` restore-tests every dump into a throwaway
  database. New `ops/docker-restore.sh` restores into a separate database and
  swaps it in only on success, keeping the old one for rollback. All of this
  is exercised against real Postgres 16.

---

## 4. Changes implemented (this branch)

| File | Change | Addresses |
|---|---|---|
| `package-lock.json` | `next` 16.3.0→16.3.6, `nodemailer` 9.0.5→9.1.1, `sharp` 0.35.3→0.35.4, `qs`, `browserslist`, `baseline-browser-mapping`; native binaries for every platform. No `package.json` range changed. | R1, R11, R12 |
| `docker-compose.yml` | Ports bound to `${LEGION_BIND_ADDRESS:-127.0.0.1}`; log rotation on every service; frontend waits for a healthy backend; Postgres `stop_grace_period: 60s` | R5, R23, R30 |
| `docker-compose.monitoring.yml` | Prometheus bound to `127.0.0.1` | R5 |
| `install.sh` | Never rewrites `.env`; refuses on missing secrets or orphaned DB volume; validates URL/HTTPS/cookie/bind consistency before building; pre-upgrade backup (abort on failure, `LEGION_SKIP_BACKUP=1` override); pulls Postgres/Redis updates, `build --pull`; readiness from Docker's healthcheck; writes `LEGION_BIND_ADDRESS` | R6, R7, R9, R13, R24, R31 |
| `ops/docker-backup.sh` (new) | `pg_dump -Fc` inside the container; TOC check; restore test into a temp DB; table-set comparison; atomic rename; SHA-256; 600/700 permissions; retention only after success; non-zero exit on any failure | R8, R27 (partly) |
| `ops/docker-restore.sh` (new) | Checksum check → restore into staging DB → rename-swap → old DB kept → rollback commands printed; live DB untouched on any failure | R8 |
| `ops/tests/*.sh` (new) | 26 real-Postgres checks, 35 installer checks, compose regression guard | tests |
| `.github/workflows/ci.yml` (new) | shellcheck, compose guard, installer tests, backup/restore e2e, `npm audit --audit-level=high`; app typecheck/test/build (fails loudly while `server/`/`frontend/` are absent) | R22 |
| `.github/dependabot.yml` (new) | Weekly npm, Actions and compose image updates | R22, R13 |
| `.gitignore` | `backups/` (dumps contain all tenants' data) | data exposure |
| `WAZUH.md`, `WINDOWS-NODE.md`, `BACKUP.md`, `INSTALL.md`, `README.md` | Correct tenant-ID lookup; removed demo credentials; Docker backup/restore; network-exposure and first-admin warnings; documented webhook limitations | R25, R26, R2, R5, R8 |

---

## 5. Fix designs for the code that was not provided

Implement these as soon as `server/`, `frontend/` and `integrations/` are in
the repository. Each is the simplest design that closes the risk.

### 5.1 Webhook authentication (R2)

1. Table `webhook_credentials(id, tenant_id, secret_encrypted, created_at,
   revoked_at)`. The secret is random per credential and encrypted with a
   key-encryption key from the environment (ADR-003). Keep two active
   credentials per tenant so secrets can rotate without downtime.
2. Headers: `x-legion-key-id`, `x-legion-timestamp`, `x-legion-signature =
   hex(HMAC-SHA256(secret, timestamp + "." + raw_body))`. Verify over the
   **raw bytes** (`express.raw()` on this route only, before any JSON
   parser), constant-time compare.
3. Reject `|now − timestamp| > 300 s`. Replay store: `INSERT INTO
   webhook_nonces(key_id, signature) … ON CONFLICT DO NOTHING`, rows expiring
   after 10 minutes. Postgres, not Redis, so a Redis outage can't disable the
   replay protection.
4. The tenant comes from the credential, never from a header.
5. Keep the old header for one release behind `LEGACY_WEBHOOK_AUTH=true`,
   logged loudly, then remove it.

### 5.2 Receive → persist → notify → confirm (R3, R4, R19)

1. In **one transaction**: insert the alert (`ON CONFLICT DO NOTHING`)
   **and**, only if it was inserted, insert `outbox` rows (`alert_email`,
   `alert_realtime`), each with `status`, `attempts`, `next_attempt_at`,
   `last_error`.
2. The request returns 202 once the transaction commits. Delivery never runs
   inside the webhook request.
3. A worker in every instance claims due rows with `SELECT … FOR UPDATE SKIP
   LOCKED`, sends, and marks `sent`. On failure it backs off exponentially
   (1 min → 6 h); after N attempts the row is marked `dead` and shown as a
   banner in the dashboard.
4. Because retries come from the outbox, a duplicate webhook can safely stay
   a no-op: the side effects were recorded when the first copy was stored.
5. `/health/ready` reports DB, Redis, SMTP reachability, oldest pending
   outbox age, and dead-letter count. Alert on "oldest pending > 5 min" or
   "dead > 0".
6. `custom-legion.py`: on any non-2xx or connection error, append the alert
   to a spool file and retry older spooled alerts on each run. The server's
   dedup makes this safe.

### 5.3 Secrets at rest (R10, R17)

- Reset/invite tokens: store `sha256(token)`; look up with `WHERE
  token_hash = $1`. Timing is irrelevant because the attacker can't choose
  the hash. Single-use (`used_at`), short expiry, invalidate on password
  change.
- TOTP secrets: AES-256-GCM with a key from the environment (not
  `JWT_SECRET`), with the key version stored beside the ciphertext.
- Backups: `gpg --symmetric` or `age` before they leave the server.

### 5.4 Realtime you can trust (R14)

The WebSocket carries hints, not data. Every alert has a monotonic
`(created_at, id)` cursor. On connect and every reconnect the client calls
`GET /alerts?since=<last cursor>` and merges the result; the socket then
tells it only "something new — refetch". A lost pub/sub message or a Redis
outage delays the screen by one poll (also poll every 30–60 s) instead of
dropping an alert.

### 5.5 Edge hardening (R15, R16)

- `app.set('trust proxy', 1)` exactly when a proxy is configured
  (`TRUST_PROXY_HOPS` env), never `true`. Log the effective client IP once
  at startup for verification.
- For login and MFA, fall back to an in-memory limiter when Redis fails
  instead of passing everything through.
- WebSocket upgrade: reject when `Origin` is not exactly `FRONTEND_URL`'s
  origin, and set the session cookie `SameSite=Lax` or stricter.

### 5.6 Bootstrap (R18)

First-admin creation under `pg_advisory_xact_lock(<const>)` inside the
transaction, re-checking "no users exist" after taking the lock. Optionally
require a one-time setup token printed by `install.sh`.

### 5.7 AI (R20)

Treat AI output as advisory: label it in the UI ("AI suggestion — verify"),
never let it change alert state automatically, cap what it receives (no raw
`full_log` by default), strip control/markup characters, and run with a
short timeout so the deterministic path always answers. Offer a per-tenant
"AI off" switch (ADR-010).

---

## 6. Tests performed (exact commands, real results)

| Command | Result |
|---|---|
| `npm audit --package-lock-only` (original lockfile) | **6 vulnerabilities: 1 critical, 3 high, 2 moderate** |
| `npm audit fix --package-lock-only` (scratch copy), then `npm ci --ignore-scripts` | 337 packages installed; `next 16.3.6`, `nodemailer 9.1.1`; **0 vulnerabilities** |
| `npm audit --package-lock-only` (committed lockfile) | **found 0 vulnerabilities** |
| Original `install.sh` with a `.env` lacking `JWT_SECRET` | **Reproduced R6**: DB password replaced, `FRONTEND_URL`→localhost, `SMTP_HOST` wiped |
| `bash ops/tests/test-backup-restore.sh` (Docker 29.3.1, `postgres:16-alpine`) | **26/26 passed**: backup + restore test, 600/700 perms, table drop → restore brings 40 alerts back, truncated dump rejected with live DB untouched, tampered dump rejected by checksum, backup with DB stopped exits non-zero with no file, installer refuses with orphaned volume and with damaged `.env` |
| `bash ops/tests/test-install.sh` (fake docker) | **35/35 passed**: fresh install, re-run keeps `.env` byte-for-byte, damaged `.env`, orphaned volume, 4 misconfigurations caught before build, LAN opt-in, backup-before-build, failed backup aborts, override, unhealthy readiness |
| `bash ops/tests/test-compose.sh` on the new files | passed |
| Same test on the **original** compose files | **8 failures**: 3 ports on every interface, 4 services without log rotation, frontend not health-gated (the test catches the original problems) |
| `docker compose -f docker-compose.yml -f docker-compose.monitoring.yml -f docker-compose.prod.yml config` | valid |
| `shellcheck install.sh ops/*.sh ops/tests/*.sh` | clean |
| `yamllint -d relaxed`, `actionlint` on workflow/compose | no errors (line-length warnings only) |

**Not tested / blocked**

| Item | Reason |
|---|---|
| Existing 134-test suite, `tsc`, `next build`, lint | **Blocked:** `server/` and `frontend/` are not in the repository |
| Auth, MFA, token reuse, tenant isolation, webhook signature/replay/duplicate, outbox, Redis outage, WebSocket reconnect, AI | **Blocked:** code not available; §5 has the designs and CI will run the suite once it is committed |
| Full `./install.sh` build and boot | **Blocked:** no Dockerfiles (`./server`, `./frontend`) |
| Real Wazuh end-to-end | **Blocked:** no Wazuh manager here, and `integrations/` is missing |
| Windows install with the new lockfile | **Not tested:** Linux sandbox; the lockfile now contains the win32 binaries |
| Behaviour of `next` 16.3.6 / `nodemailer` 9.1.1 with Legion's code | **Not tested:** in-range updates, but no build was possible |

---

## 7. Production readiness — factual assessment

**Ready (verified here):**
- Dependency set: no known high/critical advisories; CI enforces it.
- Docker network exposure: loopback by default; the database and Redis are
  never published.
- Install/upgrade safety: no self-inflicted lockout; backup before every
  upgrade; images refreshed.
- Backup and restore for the Docker install: automated, restore-tested,
  checksummed, rollback-safe; exercised against real Postgres 16.

**Not ready:**
1. **Alert delivery reliability (R3, R4, R14, R19).** Nothing guarantees that
   a stored alert reaches a person, or that an alert fired during an upgrade
   reaches Legion. This is the product's core promise.
2. **Webhook authentication (R2).** Forgeable and replayable events.
3. **Secrets at rest (R10, R17), edge settings (R15, R16), bootstrap (R18)**
   are unverified or weak by the project's own description.
4. **Never tested against real Wazuh (R28).**
5. **Unaudited code.** The application itself (`server/`, `frontend/`,
   `integrations/`, `deploy/nginx.conf`) has not been reviewed in this audit.

**Before production, in order:**
1. Commit the complete project (all directories) to this repository.
2. Implement §5.2 (outbox + spool) and §5.1 (webhook v2), with tests.
3. Verify or fix R10, R16, R17, R15, R18 in code.
4. Run an end-to-end test with a real Wazuh manager: normal delivery, Legion
   stopped during an alert, SMTP down, Redis down, duplicate delivery.
5. Schedule `ops/docker-backup.sh` with failure alerts, encrypt, copy off-site;
   do one timed restore drill on the production host.
6. Put the HTTPS proxy in place and review `deploy/nginx.conf`.
