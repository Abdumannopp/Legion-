# Legion — final production validation (2026-10-01)

Independent validation of the codebase after phases 1–6, at commit
`351c591`, followed by the fixes for every release blocker it found.
Roles: Principal Engineer, AppSec reviewer, SRE, QA lead.

## Verdict

**Release blockers: none open in code.** The validation found three; all are
fixed and verified here:

- **RED-1:** unauthenticated sign-in attempts blocked the event loop. Fixed;
  `auth-load-probe.mjs` 4/4 (it was 0/4).
- **RED-2:** high-severity advisories in nodemailer. Fixed; `npm audit` clean.
- **RED-3:** GitHub CI was red at `351c591` (the release gate failed on three
  jobs, and a fourth failure was hidden behind them). Fixed. **GitHub Actions
  run #20 on `aafdead` is green, including the release gate:**
  https://github.com/Abdumannopp/Legion-/actions/runs/36802186042

**Technically ready to release from CI's point of view.** "Production ready"
still needs the staging checks in the YELLOW list: real SMTP, Paddle
sandbox, TLS between Wazuh and Legion, a soak test, and an external pentest.

Everything else that could be tested here is verified. That includes a real
Wazuh manager, a black-box attack run on the production build, and load across
three instances. The remaining YELLOW items are known limitations or
environment gaps, not defects found.

Every claim below points to evidence in `ops/validation/2026-10-01/` or a
script that reproduces it.

---

## 1. GREEN — verified

| # | Area | Evidence | Next action |
|---|---|---|---|
| G-1 | **Authentication**: sign-up email confirmation, one-time links, no account enumeration, forged JWTs (tampered payload, `alg=none`, foreign key) refused, 15-min access tokens with issuer/audience | `production-probe.mjs` (production build, NODE_ENV=production): 18 auth checks pass — `probe.log` §sign-up/auth. `auth-hardening`, `session-token-hardening`, `saas-signup-billing` suites | Keep the probe in CI (added) |
| G-2 | **MFA**: password alone yields a challenge only; challenge token is not a session; wrong, enrolment-reused and replayed codes refused; enabling MFA ends older sessions; per-account code-guess limit | Probe §MFA (10 checks) with real RFC 6238 codes; `mfa.test.ts` | — |
| G-3 | **Authorization / RBAC**: a viewer cannot create sensor keys, invite, read the audit log, create agents, change settings, or promote itself | Probe §RBAC (8 checks, user invited by real email); `api.test.ts`, `authorization-hardening.test.ts` | — |
| G-4 | **Tenant isolation / IDOR / BOLA**: two real organisations. A cannot read, change, explain, revoke, rotate, pause or kill anything of B's, change or delete B's people, switch into B's workspace, or see B's agent decisions. A tenant id inside a webhook payload cannot steer an event into B | Probe §IDOR (17 checks, B's data verified untouched afterwards); `cross-tenant-attacks` (route-coverage map), `tenant-isolation-sweep`, `tenant-query-guard` | — |
| G-5 | **Webhook forgery and replay**: missing headers, wrong secret, unknown key, stale/future timestamp, another org's secret, body changed after signing, and byte-for-byte replay all refused; >1 MB refused before parsing; failed authentication throttled per address while the real sensor keeps working | Probe §webhook (13 checks); `webhook-auth`, `webhook-constant-time` | — |
| G-6 | **Secret leakage**: no secret, password, key, JWT secret, encryption key or metrics token in the server log, emails or sampled responses; sensor, agent and TOTP secrets and passwords not stored in plaintext; no stack traces in errors | Probe §secret leakage (7 checks, scans the process log and the database); `secrets-at-rest`, `ai-safety`. Evidence directory scanned: no secrets | — |
| G-7 | **Session security**: cookies `HttpOnly; Secure; SameSite` (refresh cookie `Strict`, path `/auth`); refresh rotation; logout kills the refresh token; a password change invalidates every older access token | Probe §sessions (4 checks) + cookie checks; `sessions.test.ts` | — |
| G-8 | **WebSocket**: foreign Origin, no Origin and no session all refused before any database work; a live socket gets only its own workspace's alerts, also across instances | Probe §WebSocket (6 checks). Load test: every alert reached its own workspace's socket across 3 instances, none foreign (20 workspaces, 3,000 alerts) | — |
| G-9 | **CORS / CSRF**: foreign origin gets no ACAO; the dashboard origin exact, with credentials, never `*`; cross-site state change refused | Probe §headers (3 checks) | — |
| G-10 | **CSP / security headers**: API `default-src 'none'`, nosniff, framing refused, Referrer-Policy, HSTS when served for https, no X-Powered-By, `/health` up/down only. Dashboard: a fresh nonce per response with `strict-dynamic`, no `unsafe-eval`, `object-src 'none'`, `frame-ancestors 'none'`, X-Frame-Options DENY | Probe §headers (dashboard via `next start` of the production build) | See Y-9 |
| G-11 | **Rate limiting**: sign-in attempts per address → 429 + Retry-After; webhook auth failures; an untrusted peer cannot choose its address with X-Forwarded-For; after the RED-1 fix, the per-account limit holds at exactly 20 across 3 instances under concurrency | Probe §rate limiting (the spoofing check binds the API to the LAN interface); `authload-after-fix.log`, `load-after-fix.log` | — |
| G-12 | **Unsafe production config refused**: e.g. `COOKIE_SECURE=false` refuses to boot; demo data never seeded in production even when asked | Probe §boot; `config-safety`, `secret-placeholders` | — |
| G-13 | **PostgreSQL failure/restart**: the sensor spools while Postgres is down; events land exactly once on return; a blip mid-burst loses and duplicates nothing; 503 + Retry-After rather than 500 | `reliability-failover`, `reliability-ingestion` (real processes; `LEGION_REQUIRE_FAILURE_INJECTION=1`, nothing skipped) | — |
| G-14 | **Redis failure/restart**: frames wait in Postgres and go out when Redis returns; tabs never miss or duplicate an alert | `alert-delivery-durability`, `realtime-recovery`, `reliability-failover` (real `redis-server` restarts) | — |
| G-15 | **Worker / application restart**: work queued when a process dies is delivered by the next; a job claimed by a SIGKILLed worker is reclaimed after its lease and sent once | Same suites, plus the **load test**: one of 3 instances SIGKILLed mid-burst → all 1,000 events accepted (sensor retried elsewhere), 2,500/2,500 due emails delivered, 0 duplicate Message-IDs, 0 dead letters (`load.log` burst 2) | — |
| G-16 | **SMTP failure, queue backlog, retry exhaustion**: mail failing during a 1,000-event burst; backlog visible in `/health/outbox` (1,760 pending, 127 retrying); drained after recovery with no dead letters; permanent failure → dead → visible → requeue → sent once | Load test burst 2; `notification-outbox`, `reliability-failover` ("a mail server that stays down exhausts the retries…") | Lease length, see Y-6 |
| G-17 | **External AI failure/timeout**: a provider that never answers is abandoned at the timeout and the local explanation returned; no silent fallback to another provider; AI output treated as data | `ai-hardening`, `ai-provider`, `ai-output-is-data` | Y-8 |
| G-18 | **Wazuh unavailable / Legion unavailable to Wazuh**: pull integrations back off, show their failures and are parked; push events spool on the manager and drain exactly once | Real manager test (below); `integrations.test.ts`; `test_custom_legion.py` (23 tests) | — |
| G-19 | **Duplicate events**: 10% re-sent during a 3,300-request burst → exactly one alert per distinct event per workspace; duplicates also collapse across instances and concurrent deliveries | Load test burst 1; `alert-delivery-durability` ("10 times concurrently"), `reliability-failover` ("two instances at once") | — |
| G-20 | **Recovery after reconnect**: a real Wazuh manager kept firing while Legion was stopped; the integration spooled on the manager; after restart the spooled and the new event each arrived exactly once and the spool emptied | `e2e-wazuh-manager.mjs` (`wazuh-manager.log`, Legion-down section) | — |
| G-21 | **Real end-to-end Wazuh flow**: **real Wazuh manager 4.9.2** (Docker) analysing sshd log lines → its brute-force rule (level 10, T1110) → `integrations/custom-legion` inside the manager → Legion webhook (production build) → PostgreSQL → outbox → worker → **email to the confirmed address** (SMTP) and **WebSocket frame to the open dashboard** → API. About 3.3 s from log line to API. The manager's own CIS benchmark findings also flowed in. No secret in the manager's integration log | `e2e-wazuh-manager.mjs`: 22/22 (`wazuh-manager.log`); `e2e-wazuh.mjs`: 34/34 | Y-4 |
| G-22 | **AI security**: prompt injection (direct and indirect), malicious logs, malicious and changed MCP tool descriptions, tool abuse, privilege escalation, exfiltration, MCP and A2A abuse, unauthorized sensitive actions, impersonation, compromised agents, kill switch and quarantine bypass | Attack assessment: **63 scenarios: 61 DEFENDED, 2 PARTIAL, 0 NOT DEFENDED**; provenance VALID for commit `351c591`, clean tree (`assessment-results.txt`). Agent security suite 459/459; package 802/802. Built API: the poisoned Wazuh username cannot make the agent resolve alerts (`e2e-wazuh`); cross-workspace SQL quarantines the agent; approve-once; resume; emergency stop with key revocation (`e2e-journeys`) | Y-1, Y-2, Y-3 |
| G-23 | **Scalability**: 3 instances, shared Postgres and Redis; 20 workspaces signed up concurrently; 100 dashboard users reading during the burst; 3,300 webhooks at concurrency 64 → **351 req/s, p95 324 ms, p99 459 ms, 0 errors**. Dashboard reads (45k requests): p95 43–51 ms, p99 ≈ 310 ms, no 5xx. Peak Postgres connections 31 (pool bound 30 + sampler). 1,500 emails, exactly one each | `load-validation.mjs` (`load.log`, `load.json`): 20/21 (the failure was RED-1); after the fix 21/21, reads max 0.56 s (`load-after-fix.log`) | Y-5 |
| G-24 | **Quality gates**: all pass (table in §4) | `quality-gates-summary.txt`, `server-tests-after-nodemailer-upgrade.txt` | — |
| G-25 | **Main user journeys** in a browser against the built API and dashboard (sign-up → workspace → connect Wazuh → first alert → incident → agent → permission change → approve/block → kill switch → billing → error → another language): 77/77 | `e2e-journeys.mjs` (gate log) | — |
| G-26 | **Backup / restore** against real Postgres (dump, verify, restore, failure modes) | `test-backup-restore.sh`: all checks pass | — |

## 2. YELLOW — known limitation / remaining risk

| # | Item | Evidence | Affected area | Next action |
|---|---|---|---|---|
| Y-1 | Assessment **EP-4 (Medium, PARTIAL)**: an *analyst* can delegate tier-2 tool authority (shell execute, cloud write) to an agent. Analysts and admins have the same permission ceiling | `assessment-results.txt` | Agent permissions model (`packages/agent-identity/src/permissions.ts` ROLE_CEILING) | Decide the policy. If analysts should not hand out tier-2, cap them or require admin co-signature for tier-2 delegations |
| Y-2 | Assessment **IMP-5 (Medium, PARTIAL)**: inside the agent-identity package, a "named external system" label is an audit label, not authentication. Legion's real webhook does verify HMAC + nonce + timestamp (G-5), so this does not apply to Wazuh today | `assessment-results.txt`; probe §webhook | Any future route using `externalSystem()` | Require signature verification in every route that uses it (lint or review rule) |
| Y-3 | The attack assessment and tests were written by the same team that built the defences; no third-party red team | — | AI agent layer | External pentest / AI red-team before GA |
| Y-4 | Real Wazuh run used **one manager (4.9.2)** with locally injected log lines, no enrolled agents, and plain HTTP over loopback. TLS between manager and Legion (production `https` hook URL behind the reverse proxy) was not exercised | `wazuh-manager.log` | Integration / edge | Staging run: enrolled agents, `https` hook through the real proxy (DEPLOY-ONLINE.md), Wazuh 4.x LTS versions customers run |
| Y-5 | Load test ran on **one host** (3 instances, local Postgres/Redis, client on the same machine): figures are relative, not a capacity plan. No soak test, no multi-AZ or managed-database latency | `load.log` | Capacity planning | Staging load test with production-like topology; 24 h soak; set SLOs and alerts on `/health/outbox` age |
| Y-6 | After a crash, emails a dead instance had claimed wait out the **120 s outbox lease**: 117 s drain after recovery in the load test. No loss and no duplicates, but alert email can be ~2 min late after a crash | `load.log` burst 2 | `server/src/outbox.ts` (`LEASE_SECONDS`) | Acceptable for email; consider a shorter lease plus heartbeat renewal if latency matters |
| Y-7 | **Email via a local SMTP sink**, not a real provider: STARTTLS, SMTP AUTH and provider throttling were not exercised. **Paddle** live checkout not exercised (no sandbox reachable); billing webhooks are covered by integration tests only | probe / load logs; `saas-signup-billing` | Notifications, billing | Staging: real SMTP provider with TLS + auth; Paddle sandbox end-to-end including webhook retries |
| Y-8 | External AI tested with stubs and timeouts, not a live provider (no keys here) | `ai-hardening`, `ai-provider` | AI explanations / copilot | Smoke test with real OpenRouter/Groq keys in staging, including provider errors and rate limits |
| Y-9 | Dashboard CSP keeps `style-src 'unsafe-inline'` (Tailwind/React inline styles). Script execution is nonce-locked | probe §headers (dashboard CSP recorded) | Frontend | Low risk; move to style nonces or hashes when practical |
| Y-10 | The response leak scan is a sample (credential list, issuance and error responses), not every response | probe §secret leakage | — | Extend the probe to record every response body |
| Y-11 | The real-Wazuh and load scripts need Docker, several minutes and a dedicated host, so they are **not in CI**. The production probe, browser journeys and the sign-in-under-load check are | — | Release process | Run them as a pre-release job on a self-hosted runner |
| Y-12 | Under a sign-in flood, sign-in itself now answers 503 + Retry-After once the hashing queue is full (8 jobs per worker). The rest of the API is unaffected, but a large enough botnet can still make sign-in slow or briefly unavailable | `password-busy.test.ts`; `authload-after-fix.log` | Sign-in availability | Per-address limits at the edge (WAF/CDN) in front of `/auth/*`; tune `PASSWORD_HASH_WORKERS` / `PASSWORD_HASH_MAX_PENDING` per host |

## 3. RED — release blocker

### RED-1 (RESOLVED): password hashing blocked the event loop

`bcryptjs` (pure JS, cost 12) runs on the main thread. This yields an
unauthenticated, low-rate denial of service and a weakened brute-force limit.

**Evidence before the fix** (`ops/tests/auth-load-probe.mjs`,
`authload-before-fix.log`; also `load.log` §rate limits):

- **`/health` latency during 30 concurrent failed sign-ins:** p50 3 ms → p50
  1,531–2,796 ms, max 9.8–24.4 s (two runs). Everything on the instance
  waits, including webhook ingestion, dashboard reads and WebSocket
  heartbeats. The sign-in endpoint needs no valid account: unknown users also
  get a dummy hash for timing equality.
- **Attacker cost:** the per-address limit is 10 attempts/min, and one
  instance handles ~3–6 hashes/s. About **30–35 source addresses** keep one
  instance saturated indefinitely.
- **Side effect on the shared brute-force limit:** delayed Redis replies
  exceed the 250 ms limiter timeout. Each instance then logs "Redis
  unavailable, counting locally" (79 / 7 / 10 times while Redis was healthy)
  and counts per instance for 5 s. The per-account limit of 20 failed
  sign-ins then let through **36–55 failures across 3 instances**. It holds at
  exactly 20 when the instances are idle.

**Affected area:** `server/src/index.ts` (login, register, accept-invite,
change-password, MFA disable via `bcrypt.*`) and `server/src/ratelimit.ts`
(`ResilientStore` timeout and cooldown).

**Fix:**

1. **`server/src/passwords.ts`:** password and recovery-code hashing run on a
   pool of worker threads, using the same bcryptjs, so every existing
   `$2a/$2b` hash keeps working. By default there is one worker per CPU,
   keeping one CPU for the event loop, at most 4.
2. **Bounded queue:** at most 8 pending jobs per worker
   (`PASSWORD_HASH_WORKERS`, `PASSWORD_HASH_MAX_PENDING`). Past that, sign-in
   answers `503 + Retry-After: 2` with `code: "auth_busy"`, translated. A
   busy 503 does not count as a failed attempt against the account.
3. **`server/src/ratelimit.ts`:** a Redis reply that was only late puts the
   instance back on the shared count at once. Previously it counted
   per-instance for the whole 5 s cooldown. A Redis that never answers still
   gets the cooldown.

**Evidence after the fix:**

| Measure | Before | After |
|---|---|---|
| `/health` during 30 concurrent failed sign-ins | p50 1,531–2,796 ms, max 9.8–24.4 s | **p50 3 ms, max 14 ms** |
| Accepted failures for one account, 3 instances (limit 20), concurrency 1 / 12 / 30 | 23 / 48 / 48 (and 36–55 in other runs) | **20 / 20 / 20** |
| "Redis unavailable, counting locally" while Redis was healthy | 79 / 7 / 10 | **0 / 0 / 0** |
| Load test: account limit across instances | 36 | **20** |
| Load test: worst dashboard read | ~6.1 s | **0.56 s** |

Sources: `authload-after-fix.log`, `load-after-fix.log`.

Regression tests: `tests/password-hashing.test.ts` (round-trip, legacy-hash
compatibility, event-loop lag < 100 ms with 8 hashes in flight, saturation →
`HashingBusyError`, worker restart); `tests/password-busy.test.ts` (API:
503 + Retry-After + `auth_busy` in the caller's language, `/health` still
answering, sign-in works after the flood); `tests/edge-ratelimit.test.ts`
(a late reply restores the shared count; a hang keeps the cooldown; 503 is
not a failure). `auth-load-probe.mjs` now runs in CI.

### RED-2 (RESOLVED during validation): high-severity advisories in nodemailer

At `351c591`, `npm audit --audit-level=high` failed:

- **nodemailer ≤ 10.0.8 (High):** cross-tenant SMTP credential disclosure via
  a process-global DNS cache, plus parser DoS issues.
- **ip-address ≤ 10.7.0 (Moderate):** SSRF classification issues.

CI's `dependencies` job would have blocked the release (`npm-audit-before-fix.txt`).

**Fix:** nodemailer 9.1.1 → 10.0.13 (the only breaking change is "Node ≥ 20";
Legion runs Node 22) and ip-address 10.5.0 → 10.7.2 via `npm audit fix`.

**Verified:**

- `npm audit` now reports 0 vulnerabilities (`npm-audit-after-fix.txt`).
- Server typecheck and build pass; the full server suite passes 1070/1070 on
  the upgraded tree (`server-tests-after-nodemailer-upgrade.txt`).
- The production probe and load test delivered real email through the
  upgraded mailer: 2 sign-up confirmations, an invitation, and 2,500 alert
  emails with no duplicates.

**Next action:** none beyond RED-3.

### RED-3 (RESOLVED): GitHub CI was red

The earlier report said CI was "not yet run". That was wrong: GitHub
Actions runs 14–17 on this branch had all failed. At `351c591` the release
gate failed on three jobs:

- `dependencies`: the nodemailer advisories (RED-2);
- `deploy-scripts`: `shellcheck` findings — `cd` without `|| exit` in
  `ops/check-backup.sh`, `export VAR=$(…)` in `test-backup-restore.sh`, and
  sourced `ops/lib/common.sh` not followed. That failure also skipped the
  backup/restore and integration-script steps after it;
- `agent-identity`: the Wazuh e2e step ran from `packages/agent-identity`
  (script not found) with that job's database, and failed in 0 s.

Once shellcheck passed, a fourth failure surfaced that it had been hiding.
The backup/restore test exited 127 because the job never installed `age`
(backups are always encrypted), so that test had not actually run in CI.

**Fix:** the scripts are corrected and CI now runs `shellcheck -x`, which also
checks the shared library (`shellcheck-after-fix.txt`: clean). The e2e step
moved into the `app` job, which builds the server and has the matching
database (`e2e-wazuh-after-fix.log`: 34/34). The backup job installs `age`, and
the test now names any missing tool instead of exiting silently.

**Verified on GitHub:** run #20 (`aafdead`) — every job green: dependencies;
deploy scripts (shellcheck, backup/restore with age, integration script);
agent identity; security tests and attack assessment; app (server suite with
failure injection, build, Wazuh e2e, browser journeys, production probe,
sign-in under load); release gate.

---

## 4. Quality gates (fresh run on `351c591`, then re-run where the fix touched)

| Gate | Result | Log |
|---|---|---|
| Typecheck — server (`tsc --noEmit`) | pass | `quality-gates-summary.txt` |
| Typecheck — agent-identity | pass | 〃 |
| Lint — frontend (`tsc` + i18n hard-coded-text check) | pass | 〃 |
| Unit + integration — server, failure injection required | **1070 / 1070** (46 files, 0 skipped); after fix **1070 / 1070** | 〃, `server-tests-after-nodemailer-upgrade.txt` |
| Security — server (`test:security`) | **236 / 236** | 〃 |
| Unit + integration — agent-identity | **802 / 802** | 〃 |
| Security — agent-identity (`test:security`) | **459 / 459** | 〃 |
| Attack assessment + provenance | 63 run: 61 DEFENDED, 2 PARTIAL (Medium), 0 NOT DEFENDED; provenance VALID | `assessment-provenance.txt`, `assessment-results.txt` |
| Unit — frontend | **154 / 154** | 〃 |
| Production build — agent-identity, server, frontend | pass | 〃 |
| E2E — Wazuh integration script → API → agent (`e2e-wazuh.mjs`) | **34 / 34** | 〃 |
| E2E — browser journeys (`e2e-journeys.mjs`) | **77 / 77** | 〃 |
| E2E — real Wazuh manager (`e2e-wazuh-manager.mjs`, new) | **22 / 22** | `wazuh-manager.log` |
| Black-box production probe (`production-probe.mjs`, new) | **106 / 106** | `probe.log`, `probe.json` |
| Load / scalability (`load-validation.mjs`, new) | **20 / 21** (fail = RED-1) → after fix **21 / 21** | `load.log`, `load-after-fix.log` |
| Auth under load (`auth-load-probe.mjs`, new) | **0 / 4** (RED-1) → after fix **4 / 4** | `authload-before-fix.log`, `authload-after-fix.log` |
| After the RED-1 fix: server suite / server security / probe / journeys / e2e-wazuh | **1081 / 1081**, **236 / 236**, **106 / 106**, **77 / 77**, **34 / 34** | `*-after-fix.*` |
| shellcheck (`-x`) | fail at `351c591` → clean | `shellcheck-after-fix.txt` |
| Integration script (`test_custom_legion.py`) | **23 / 23** | gate log |
| Backup / restore against Postgres | pass | gate log |
| CI gate self-test | 10 / 10 | gate log |
| `npm audit --audit-level=high` | **fail at `351c591`** → pass after RED-2 fix | `npm-audit-*.txt` |

Environment: Node 22.22, PostgreSQL 16.13, Redis 7.0.15, Chromium (Playwright
1.56), Docker 29.3 with `wazuh/wazuh-manager:4.9.2`.

## 4a. Addendum 2026-10-02 — denial-of-service resilience

Question asked: can the platform withstand a DDoS? Measured with
`ops/tests/ddos-resilience.mjs` (attackers in separate processes; a legitimate
dashboard user, a signing Wazuh sensor and a person signing in are measured the
whole time). One machine, so the numbers describe **behaviour**, not capacity.

**Found and fixed (each with a regression test):**

| Finding | Evidence | Fix |
|---|---|---|
| Once the rate-limit table was full, every call swept all 50 000 entries: ~600 µs per call per limiter, so a flood from many addresses pinned a CPU inside the limiter | CPU profile of the main thread | Entries kept in expiry order, sweep stops at the first live entry: ~1.5 µs (`server/src/bounded-counter.ts`, `server/tests/edge-ratelimit.test.ts`) |
| Keys that did not fit shared ONE overflow counter: a flood from more than `RATE_LIMIT_MAX_KEYS` addresses throttled every new legitimate address | unit test | 256 overflow counters chosen by a per-process salted hash, so an attacker cannot aim at a bucket |
| TCP connections that never sent a byte were never closed (Node's header timeout starts at the first byte); 3 500 silent sockets stayed forever | A4 | `HTTP_FIRST_REQUEST_TIMEOUT_SECONDS` (15 s): `server/src/edge.ts`, `server/tests/silent-connections.test.ts` |
| nginx had no per-address connection limit, no timeouts for slow clients, no real-IP handling behind a CDN (all visitors one bucket) | Part B | `deploy/nginx.conf`, `ops/update-cloudflare-ips.sh` + systemd timer, `DEPLOY-ONLINE.md` §12 |

**Measured, Part A (API alone, production mode, full scale, 39 checks pass):**
distributed floods from thousands of source addresses, 2 × 120 connections:

| Flood | Throughput absorbed | API CPU | Legitimate traffic during it |
|---|---|---|---|
| unauthenticated reads / 404s | 2 900 req/s | 1.2 cores | reads and sensor events succeed, 0 lost; latency up from ~6 ms to ~0.5–2 s |
| forged webhooks | 1 800 req/s | 1.2 cores | same |
| sign-in guesses (a password hash each) | 1 060 req/s | 4 cores (hash workers) | sensor + reads OK; **sign-in returns 503 `auth_busy` for most attempts (1 of 7 succeeded)** — the hash queue is the part an attacker can crowd |
| all combined | 1 500 req/s | 3.8 cores | reads/sensor OK, 0 lost; sign-in mostly 503 |

Recovery: latency back to baseline (p95 < 20 ms) within the 4 s window after
every flood. 10 MB bodies: refused 413 (2 499 refused, none accepted), memory
plateaus (second round +10 MB). 3 500 idle / slow-loris sockets: all closed by
the server in 15.0–15.3 s, legitimate traffic unaffected. API healthy and no
unhandled errors in its log afterwards.

**Measured, Part B (real nginx 1.24 running `deploy/nginx.conf`, 17 checks pass):**
`nginx -t` accepts the config with the generated Cloudflare snippet; 80
sign-ins in a burst → 59 refused by nginx itself (never reach Node), 10 reach
the API and the 11 after that are refused by Legion's own limit; 400 junk API
requests → ≥150 cut at nginx; the sensor webhook is never rate-limited by
nginx; behind a trusted CDN the throttled visitor stays throttled while a second
visitor is unaffected, and Legion itself sees the real addresses (its per-address
sign-in limit holds for X, not Y); from an **untrusted** sender, rotating a forged
`CF-Connecting-IP` over 60 values escapes nothing; slow-loris dropped at 15.0 s;
320 half-sent requests from one address make the 321st connection a 429 while
another visitor is served.

**YELLOW (new, remaining):**
- Volumetric (L3/L4) attacks cannot be mitigated on the server at all; they need
  a CDN/scrubbing provider in front (DEPLOY-ONLINE.md §12).
- Sign-in is the cheapest thing for a botnet to crowd: while the flood lasts,
  most sign-ins from a NEW browser get `503 auth_busy` (the rest of the API keeps
  working). Mitigated since (see the second addendum): known devices use a
  priority lane, and Turnstile can be switched on.
- Per-address limits remain weak against more distinct addresses than the
  tables hold; the blast radius is now bounded (see above) but not zero.
- Not tested: Cloudflare itself (needs an account; this sandbox cannot reach
  challenges.cloudflare.com either) — in particular the recommended WAF skip
  rule for the Wazuh webhook path, and `ufw` origin lockdown (only the dry-run
  output is generated and shellchecked). `ops/check-cloudflare-setup.sh` checks
  the operator's real setup instead.
- The tests run on one machine; capacity planning needs a load test on the real server.

Reproduce: `node ops/tests/ddos-resilience.mjs [--part a|b]` (in CI at half scale).

### Second addendum 2026-10-02 — sign-in under a botnet, and the Cloudflare tooling

| Change | Evidence |
|---|---|
| **Priority lane for known devices.** The hash pool now queues jobs in the main thread and gives each worker one at a time, most urgent first. A browser that completed a sign-in (both factors) holds a signed `legion_device` cookie for that account; its next sign-in to the same account is hashed from a separate lane the flood cannot fill (max 10/min per account). Signed-in password confirmations use it too. | `server/tests/password-hashing.test.ts` (priority overtakes the queue; full normal lane still admits priority; own bound), `password-busy.test.ts` (under a flood: known device → 200, same request without cookie → 503, cookie for another account or forged → 503, cookie never replaces the password), `known-device.test.ts`. ddos-resilience A (41 checks): during the sign-in floods, **new-browser sign-ins 3 of 15 succeeded (12 × 503); known-device sign-ins 5 of 5 succeeded**, 19 of 19 over the whole run. |
| **Turnstile (optional).** `TURNSTILE_SECRET_KEY` + `NEXT_PUBLIC_TURNSTILE_SITE_KEY`: login, register, forgot-password, resend-verification require a solved challenge, verified before any hash or email and **before the per-account counters** (otherwise challenge-less requests could lock a victim's account or spend its email budget). Fails closed (503), bounded (256 in flight, 5 s). CSP admits challenges.cloudflare.com only when configured. | `server/tests/turnstile.test.ts` (15; the two victim-protection tests fail when the middleware order is reversed — checked), `frontend/lib/csp.test.ts`, `ops/tests/e2e-turnstile.mjs` (22 checks in Chromium against the built dashboard and API; Cloudflare's script and siteverify replaced by stand-ins). |
| **Wazuh sensor behind Cloudflare.** A Cloudflare challenge/block (403/503 page, `cf-mitigated`) used to be treated as Legion refusing the event → set aside in `dead/`, never re-sent. Now it is spooled and re-sent automatically, with a log line naming the fix; the request carries a named User-Agent instead of `Python-urllib`. | `integrations/test_custom_legion.py` (26) |
| **`ops/check-cloudflare-setup.sh`**: DNS proxied, answers via Cloudflare, dashboard loads, http→https, webhook not challenged, origin closed (`--server-ip`), on the server: snippet loaded and fresh, timer, ufw, access log shows visitor addresses. | `ops/tests/test-check-cloudflare.sh` (20: a correct setup passes; grey-cloud DNS, challenged webhook, unproxied answers, open origin, site down, Cloudflare addresses in the access log are each caught) |

Still not verified: the real Cloudflare service (Turnstile widget and siteverify,
WAF rules). An operator can run the same DoS test on their own server
(DEPLOY-ONLINE.md §12.9) to replace the one-machine numbers with their own.

## 5. Reproduce

```bash
npm ci && npm run build                     # agent-identity, server, frontend
export E2E_ADMIN_DATABASE_URL=postgresql://legion:…@127.0.0.1:5432/postgres
node ops/tests/production-probe.mjs         # black-box security probe (in CI)
node ops/tests/e2e-journeys.mjs             # browser journeys (in CI)
node ops/tests/e2e-wazuh-manager.mjs        # real Wazuh manager (needs Docker)
node ops/tests/load-validation.mjs          # 3 instances + Redis load test
node ops/tests/auth-load-probe.mjs          # RED-1 regression (in CI)
node ops/tests/ddos-resilience.mjs          # flood / slow clients / real nginx (in CI)
```

Each script creates and drops its own database. They share helpers in
`ops/tests/lib/harness.mjs`: the built API as a real process, an SMTP sink,
signed sensor requests, sessions, a WebSocket client and TOTP.
