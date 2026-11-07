# Legion — re-audit of the production-readiness findings (2026-11)

Every finding of [PRODUCTION-READINESS-AUDIT-2026-09-29.md](PRODUCTION-READINESS-AUDIT-2026-09-29.md)
and every open item of [PRODUCTION-VALIDATION-2026-10-01.md](PRODUCTION-VALIDATION-2026-10-01.md)
was checked again **against the code**, not against earlier reports. Each row
says what is true now, where the evidence is, and which test guards it.

Status: **Fixed** (in code, with a regression test) · **Partial** (the risk is
reduced; what remains is named) · **Open** (not changed; why).

## Summary

| | Before this re-audit | After |
|---|---|---|
| P0 | 1 fixed | 1 fixed |
| P1 (14) | 5 fixed, 1 partial, 8 open | **10 fixed, 1 partial**, 3 open (design, legal or infrastructure decisions) |
| P2 (19) | 11 fixed, 8 open | **15 fixed, 1 partial**, 3 open (2 performance, 1 infrastructure) |
| Attack assessment | 61 defended, 2 partial | **63 / 63 defended**, 0 partial, 0 not defended |

All server (60 files, 1,111 tests), agent-identity (917), frontend (159) and
Python sensor (41) tests pass; the CI gate self-test passes 13/13; no high or
critical dependency advisory.

## High priority (P0 / P1)

| # | Finding | Status | Evidence / test |
|---|---|---|---|
| P0-1 | Source, CI, deploy assets not versioned; broken Docker path | **Fixed** (2026-09) | Repository, `ci.yml` "Docker stack builds" job |
| P1-1 | Alerts lost during an outage; large events dropped | **Fixed** (2026-09) | Sensor spool; `test_custom_legion.py`, `reliability-*` tests. Re-audit: a single broken event no longer blocks the spool (poison handling) |
| P1-2 | Boot-time migrations lock hot tables on every start, no lock timeout | **Fixed now** | `db/pool.ts`: schema fingerprint in `legion_schema_state` — an unchanged schema runs nothing; a changed one runs with `lock_timeout` 5 s and retries. `tests/migrations.test.ts` |
| P1-3 | Unauthenticated webhook traffic exempt from rate limiting | **Fixed** (2026-09) | `webhook-guard.ts`; `webhook-auth.test.ts` |
| P1-4 | Paddle webhook grants access for any price | **Fixed now** | Only prices in `PADDLE_PRICE_IDS` grant access; anything else is recorded (`billing.unrecognised_price`) and kept blocked. `saas-signup-billing.test.ts` "audit P1-4" |
| P1-5 | Events of an old subscription overwrite the current one | **Fixed now** | A late event for a superseded subscription cannot take access away from the one paying now (`billing.superseded_event`). `saas-signup-billing.test.ts` "audit P1-5" |
| P1-6 | Subscription gate not applied to the agent surface | **Fixed** (2026-09) | `subscriptionGate` on agent prefixes; `agent-security.test.ts` |
| P1-7 | AI quotas per instance, per minute only | **Fixed now** | Per-minute quota shared across instances (2026-09) **plus** a daily budget per workspace (`AI_DAILY_LIMIT`, default 1000). `scaling.test.ts` "audit P1-7" |
| P1-8 | Refresh from several tabs treated as theft | **Fixed** (2026-09) | Tabs serialise refresh; `sessions.test.ts` |
| P1-9 | systemd never restarts a crashed API | **Fixed now** | `npm start` uses `concurrently --kill-others`; unit `Restart=always`. `deploy-supervision.test.ts` really kills a child and checks the exit |
| P1-10 | No structured logs, request IDs or metrics | **Partial** | Every response carries a server-made `x-request-id`; one JSON access-log line per request (route pattern, status, latency; never URL, query, body or headers). `access-log.test.ts`. Remaining: Prometheus metrics, tracing, error tracker |
| P1-11 | No row-level security; runtime role owns tables | **Open** | Tenant scoping stays in the application, guarded by `tenant-query-guard`, `tenant-isolation-sweep`, `cross-tenant-attacks`. RLS needs every query moved into tenant-scoped transactions and a separate owner role — a large, staged change; not done in a hurry |
| P1-12 | No tenant/user deletion; backups outlive the promise | **Open (decision)** | Deletion of append-only evidence and the backup-retention number need a legal decision first (what is kept, for how long). Groundwork: the audit log's erasure switch (P2-12) and email retention (P2-16) |
| P1-13 | Nightly dump only; no PITR or HA | **Open (infrastructure)** | Backups are encrypted, verified and monitored ([RECOVERY.md](RECOVERY.md)). PITR/HA is a hosting choice: use a managed PostgreSQL with point-in-time recovery |
| P1-14 | Login timing defence broken | **Fixed** (2026-09) | Real cost-12 dummy hash; `auth-hardening.test.ts` |

## Medium priority (P2)

| # | Finding | Status | Evidence / test |
|---|---|---|---|
| P2-1 | MFA changes do not revoke sessions | **Fixed** | MFA disable revokes everywhere; `mfa.test.ts` |
| P2-2 | Refresh expiry slides forever | **Fixed** (2026-09) | `SESSION_ABSOLUTE_DAYS`; `sessions.test.ts` |
| P2-3 | Email enumeration via invitations | **Fixed** | Existing people are added as members (multi-workspace); `workspaces.test.ts` |
| P2-4 | "At least one admin" check-then-act | **Fixed** (2026-09) | Row locks in one transaction |
| P2-5 | `limit=abc` → 500; unbounded offsets | **Fixed** (2026-09) | zod-validated query strings |
| P2-6 | Alert writes serialise on the tenant row | **Open (performance)** | Not a security risk; load test: 351 req/s |
| P2-7 | Several DB round trips per request | **Open (performance)** | Not a security risk |
| P2-8 | One pub/sub channel; no socket caps or pings | **Fixed** | Per-user/tenant socket caps, liveness pings; `network-hardening.test.ts`, `realtime-recovery.test.ts` |
| P2-9 | CSP `unsafe-inline` scripts; no HSTS; no nginx limits | **Fixed** | Nonce CSP, HSTS, `limit_req` zones in `deploy/nginx.conf` |
| P2-10 | `DEPLOYMENT_MODE` unvalidated; checks keyed to `NODE_ENV` | **Fixed** | `config-safety.test.ts` |
| P2-11 | One HS256 key, no `iss`/`aud`, rotation signs everyone out | **Fixed** (2026-09) | Issuer/audience, `JWT_PREVIOUS_SECRETS` |
| P2-12 | `audit_log` mutable | **Fixed now** | A trigger refuses UPDATE and DELETE (also via cascade); only an explicit, transaction-local erasure switch allows them. `audit-append-only.test.ts`. The owner role can still run DDL — see P1-11 |
| P2-13 | Firewall hooks not wired to alerting; sweep unscheduled | **Fixed** | `agents.ts` hooks and scheduled behaviour sweep |
| P2-14 | `/health` discloses provider and version | **Fixed** | Details only for operators (`HEALTH_METRICS_TOKEN`) |
| P2-15 | Mock provider creates fake high-severity alerts in production | **Fixed now** | `/security-events/sync` exists only under `NODE_ENV=development/test`. `mock-provider.test.ts` |
| P2-16 | Sent emails, audit and decision logs grow forever | **Fixed now (emails)** | Delivered alert emails deleted after `NOTIFY_RETENTION_DAYS` (30); undelivered never touched. `retention.test.ts`. Audit/decision logs are evidence: their retention is part of the P1-12 decision |
| P2-17 | Two lockfiles; runtime needs a dev tool; artefacts in the archive | **Partial** | Fixed now: the stale `frontend/package-lock.json` (it pinned `next 16.3.0` while the build uses 16.4.4) is removed, and a test forbids a second lockfile (`deploy-supervision.test.ts`). The release zip is `git archive` of the commit (no artefacts). Remaining: `npm start` still needs `concurrently` from devDependencies, so a production install must not use `--omit=dev`; moving it changes the lockfile with this npm version in a way that would drop the musl/glibc markers Docker (Alpine) relies on, so it is left for a lockfile regeneration with the CI npm version |
| P2-18 | Secrets in plaintext `.env` | **Open (infrastructure)** | File permissions + encryption keys separate from backups; a secret manager is a hosting choice |
| P2-19 | Node keep-alive shorter than nginx's → 502s | **Fixed now** | nginx upstream `keepalive_timeout 4s`, Node pinned at 5 s; `deploy-supervision.test.ts` compares the two |

## Open items from the 2026-10-01 validation

| # | Item | Status |
|---|---|---|
| Y-1 / EP-4 | An analyst could delegate write/execute (tier 2) authority to an agent | **Fixed now**: tier 2 can be delegated by an administrator only — checked when the grant is made and at every use. `firewall.test.ts` "assessment EP-4"; assessment EP-4 → DEFENDED |
| Y-2 / IMP-5 | "External system" label without verification | **Fixed now**: `externalSystem()` requires a `verify` function and labels the caller only after it succeeds; without one every request is refused. `principal.test.ts`; assessment IMP-5 → DEFENDED |
| Y-3 | No third-party red team | Open — needs an external pentest before GA |
| Y-4, Y-5, Y-7, Y-8, Y-11 | Staging checks (TLS to Wazuh, soak test, real SMTP/Paddle/AI) | Open — need a staging environment |
| Y-9 | `style-src 'unsafe-inline'` | Open, low risk (scripts are nonce-locked) |

## CI enforcement

- The `Security tests and attack assessment` job runs the server security suite
  (now 33 files) and the agent security suite (18 files), the 63-scenario attack
  assessment, and validates that the result belongs to the exact commit.
- `.github/scripts/check-ci-gate.mjs` now also fails CI if a security regression
  test is removed from `test:security`, its file is deleted, or the security job
  stops running the suites. `ops/tests/test-ci-gate.sh` proves each case (13/13).
- **One setting only the repository owner can make:** GitHub → Settings →
  Branches → mark **Release gate** as a required status check for `main`.

## Behaviour changes to know

- `ACCESS_LOG` is on by default: one JSON line per request on stdout.
- Paddle: with `PADDLE_PRICE_IDS` set, a subscription for any other price grants no access.
- `frontend/package-lock.json` is gone: install from the repository root (as the docs and Docker already do).
- An analyst can no longer delegate tier-2 authority; existing analyst grants for tier 2 stop working at use. An administrator can re-grant.
- `/security-events/sync` returns 404 outside development/test.
- New settings: `AI_DAILY_LIMIT`, `NOTIFY_RETENTION_DAYS`, `ACCESS_LOG`, `LEGION_FORCE_MIGRATE`.
