# Legion — final production validation (2026-10-01)

Independent validation of the codebase after phases 1–6, at commit
`351c591` plus the dependency fix made during this validation (see RED-2).
Roles: Principal Engineer, AppSec reviewer, SRE, QA lead.

## Verdict

**Not production ready.** One open release blocker:

- **RED-1:** unauthenticated sign-in attempts block the event loop. That stalls
  the whole API instance and weakens the cross-instance brute-force limit.

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
| G-11 | **Rate limiting (per address)**: sign-in attempts per address → 429 + Retry-After; webhook auth failures; an untrusted peer cannot choose its address with X-Forwarded-For | Probe §rate limiting (the spoofing check binds the API to the LAN interface) | The per-account limit across instances is RED-1 |
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
| G-23 | **Scalability**: 3 instances, shared Postgres and Redis; 20 workspaces signed up concurrently; 100 dashboard users reading during the burst; 3,300 webhooks at concurrency 64 → **351 req/s, p95 324 ms, p99 459 ms, 0 errors**. Dashboard reads (45k requests): p95 43–51 ms, p99 ≈ 310 ms, no 5xx. Peak Postgres connections 31 (pool bound 30 + sampler). 1,500 emails, exactly one each | `load-validation.mjs` (`load.log`, `load.json`): 20/21 (the failure is RED-1) | Y-5 |
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
| Y-11 | The real-Wazuh, load and auth-load scripts need Docker, several minutes and a dedicated host, so they are **not in CI** (the production probe and browser journeys are) | — | Release process | Run them as a pre-release job on a self-hosted runner |
| Y-12 | Validation ran at `351c591` plus this commit's changes. The new CI step (production probe) and the dependency fix have not yet run in GitHub Actions | — | CI | Confirm the pipeline is green on this commit before tagging |

## 3. RED — release blocker

### RED-1 (OPEN): password hashing blocks the event loop

`bcryptjs` (pure JS, cost 12) runs on the main thread. This yields an
unauthenticated, low-rate denial of service and a weakened brute-force limit.

**Evidence** (`ops/tests/auth-load-probe.mjs`, `authload.log`; also
`load.log` §rate limits):

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

**Recommended next action:**

1. Move password hashing off the event loop: a `worker_threads` pool running
   bcryptjs, or a native/threadpool implementation such as `bcrypt` or
   argon2. Existing `$2a/$2b` hashes stay valid.
2. Bound concurrent hashing with a small queue per instance. Answer
   `503 + Retry-After` when it is full, rather than queueing without limit.
3. Stop treating event-loop lag as a Redis failure for the account limiters.
   Keep sending the remote `INCR` during the cooldown, and prefer
   "remote unknown → count locally **and** retry remote" over skipping it.
4. Add `auth-load-probe.mjs` to the pre-release job. It must pass: `/health`
   p50 < 250 ms under 30 concurrent sign-ins, and ≤ 20 accepted failures at
   concurrency 1, 12 and 30.

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

**Next action:** confirm CI is green on this commit (Y-12).

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
| Load / scalability (`load-validation.mjs`, new) | **20 / 21** (fail = RED-1) | `load.log`, `load.json` |
| Auth under load (`auth-load-probe.mjs`, new) | **0 / 4** (= RED-1, expected until fixed) | `authload.log` |
| Integration script (`test_custom_legion.py`) | **23 / 23** | gate log |
| Backup / restore against Postgres | pass | gate log |
| CI gate self-test | 10 / 10 | gate log |
| `npm audit --audit-level=high` | **fail at `351c591`** → pass after RED-2 fix | `npm-audit-*.txt` |

Environment: Node 22.22, PostgreSQL 16.13, Redis 7.0.15, Chromium (Playwright
1.56), Docker 29.3 with `wazuh/wazuh-manager:4.9.2`.

## 5. Reproduce

```bash
npm ci && npm run build                     # agent-identity, server, frontend
export E2E_ADMIN_DATABASE_URL=postgresql://legion:…@127.0.0.1:5432/postgres
node ops/tests/production-probe.mjs         # black-box security probe (in CI)
node ops/tests/e2e-journeys.mjs             # browser journeys (in CI)
node ops/tests/e2e-wazuh-manager.mjs        # real Wazuh manager (needs Docker)
node ops/tests/load-validation.mjs          # 3 instances + Redis load test
node ops/tests/auth-load-probe.mjs          # RED-1 regression (fails until fixed)
```

Each script creates and drops its own database. They share helpers in
`ops/tests/lib/harness.mjs`: the built API as a real process, an SMTP sink,
signed sensor requests, sessions, a WebSocket client and TOTP.
