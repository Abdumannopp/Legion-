# Legion — Security & engineering hardening: assessment and plan (Phase 1)

**Status: plan approved ("Loyiham ishonchli qilb beri", with the recommended answers to §6) and implemented —
see §0 for what was done, with evidence, and what remains. §1–§6 are the original assessment, unchanged.**
Date: 2026-11-06. Assessed: branch `claude/laughing-clarke-cmfudk` @ `9b9c56c` (the newest code).

> **Baseline warning.** `main` is at `3111404` (merge of PR #1, 2026-11-04) and is **42 commits behind** this
> branch (197 files, +17 094 / −2 557). `main` has **no SOC core at all** (no versioned migrations, no policy /
> approval / action engine, no audit chain) and none of the Task 13–15 fixes. Every statement below is about the
> branch. Deploying `main` today would ship an older, less hardened product.

---

## 0. Implementation status (2026-11-06)

Decisions taken (§6, recommended answers): plan order as proposed; 30-day floor for audit erasure; RLS behind
`DB_RLS` with CI enforcing, rolled out by table group; Semgrep (pinned) for SAST; "set the new key to today's
value, then rotate" for existing installs; separate commits on `claude/laughing-clarke-cmfudk`.
CI: run **42296435340** on `5b2cefe` is green in every job, including the release gate, Semgrep, gitleaks and
both Docker installs with the owner/runtime split. Later commits are verified locally (below) and by the next run.

| PR | Finding | Status | Commit | Evidence (regression tests) |
|---|---|---|---|---|
| PR-10a | F-08 | Done | `be282a8`, `aa93dd3` | image-scan job green; gosu removed, Postgres uid 70 |
| PR-4 | F-03 High | Done | `c8e3a2a` | `PAYMENT_HASH_KEY` mandatory in production, no constant, rotatable — payments (4 new), pilot-preflight |
| PR-5 | F-05 | Not changed, by design | — | re-rated Low: the webhook secret is a deprecated id salt only; no secret derives from it |
| PR-1 | F-01 High | Done | `3dd11a1` | default Docker API runs as `legion_app`; boot refuses a privileged role unless `NODE_ENV=development`; CI docker job asserts role, denied file/program access, no admin password in the API |
| PR-6 | F-06 Medium | Done | `c7b88f9` | `SOC_AUDIT_KEY` mandatory in production; key ring with a chained `audit_key.rotated` event — audit-key-rotation |
| PR-8 | F-09 Medium | Done | `0c58dfc` | acknowledged/resolved timestamps and actor, reopen needs a reason — alert-lifecycle |
| PR-10b–e | F-07 Medium | Done | `03cecb2`, `4bb6452`, `5b2cefe` | SBOM (syft), gitleaks (full history), Semgrep ERROR rules, all pinned + checksummed and required by the release gate; first Semgrep run found a **real** AES-GCM truncated-tag acceptance (fixed, test added) and one SQL-building pattern (moved into Postgres `format`) |
| PR-7 | IDOR | Done | `f670526` | idor-sweep: every route with a path parameter, generated from the route table; a new route fails until it has a fixture |
| PR-9 | F-11 Low | Done | `f6e5b02` | ATT&CK technique per threat sign — campaigns (3 new) |
| PR-11 | F-12 Low | Done | `1c1ae37` | IPs / CVEs / techniques not in the alert are marked "[not in the alert — verify]" — ai-hardening (2 new) |
| PR-2 | F-02 High | Done | `3c0af18`, `5b2cefe` | schema owned by `legion_owner` (NOLOGIN); API role cannot ALTER/DROP/TRUNCATE/disable a trigger; erasure only through bounded `SECURITY DEFINER` functions (30-day floor, legal hold, tombstone) — db-role-split (25), CI docker jobs assert the API owns nothing |
| PR-3a | F-04 High | Done for the first table group, **off by default** | this commit | 14 workspace-first tables under RLS (`DB_RLS=enforce`); proven as the API's role — row-level-security (12); all six end-to-end suites pass with enforcement and fail on any missing context; CI runs them enforced |
| PR-3b/c | F-04 | Open | — | users/tenants/memberships/sessions/billing/credentials/outbox/jobs/memory: their lookups happen before the workspace is known and need their own design |
| PR-12 | docs | Done | this commit | INSTALL, RECOVERY, TENANT-ISOLATION, this section, PRODUCTION-READINESS-ASSESSMENT |

Found while implementing (fixed in the same commits): a cascade from a parent row would have let a non-owner
erase audit rows under a `current_user` check (the check uses `session_user`); the sensor monitor read alerts of
every workspace in one query (now one workspace at a time); a websocket test raced the one-second JWT precision.

**Follow-up, 2026-11-07 (owner's list of six weaknesses):**

| Weakness | What was done | Evidence |
|---|---|---|
| Separating customers' data | RLS (`DB_RLS=enforce`) is now **on by default** in both Docker installs; `/metrics` counts across workspaces through an owner-run aggregate (numbers only, `0010`); demo seed and JSON import write in their own workspace | row-level-security (13), all e2e suites enforced; CI docker job asserts `DB_RLS=enforce` |
| Extra control for dangerous actions | Removing a person, changing a role, rotating/revoking a sensor key, deleting an integration and exporting the workspace need a password confirmation from the last 10 minutes (`POST /auth/step-up`, + code with MFA); the dashboard asks for it; erasing a workspace past a legal hold needs a written reason and is marked in the tombstone (`0011`) | recent-auth (7), db-role-split |
| Docker ports open to the network | `docker-compose.yml` published 8000/3000 on every interface (Docker bypasses ufw); now `127.0.0.1` unless `LEGION_PUBLISH_ADDRESS` says otherwise | CI docker job: `docker compose port` = 127.0.0.1, LAN address refused |
| A test that broke | realtime-recovery race fixed (`174f1cd`, CI green); a second, random one found in the production probe (agent-secret check split base64url on "_") fixed | CI run 42307448160; probe 106/106 |
| Old logs filling the disk | Container logs rotated (5 × 20 MB) in the default and monitoring stacks; `SOC_RETENTION_DAYS=365` by default in Docker; `legion_database_size_bytes` metric and `LegionDatabaseLarge` alert | promtool rule tests, metrics test |
| What reaches external AI | Strict mode (placeholders for IPs, e-mails, host names) is now the default for self-hosted too; card numbers (Luhn) and IBANs (mod-97) are removed in every mode, like credentials | ai-safety (2 new), ai-hardening |

**What is still not true, after all of the above** (see also §5): RLS is off by default and covers 14 of ~35
tenant tables; a single-role (bare-metal) install is not bound by it; the API's role can still erase a whole
workspace through `legion_erase_tenant` (bounded: recorded, legal hold refused unless forced — and the caller
can pass `force`); no independent penetration test; no HA. Nothing here is a SOC 2 or ISO 27001 claim.

---

## 1. Architecture and trust boundaries

```
 Internet ──TLS──► nginx / CDN (deploy/nginx.conf: limit_req, limit_conn, headers)          [TB-1: public edge]
                     │ 127.0.0.1 only
          ┌──────────┴───────────┐
          │ Next.js dashboard     │  browser holds httpOnly session cookie                    [TB-2: browser]
          └──────────┬───────────┘
                     ▼
 ┌──────────────────────────── API (Express 5, server/src/index.ts, ~2.7k lines) ───────────────────────────┐
 │ authN: password+bcrypt, TOTP MFA, JWT access + refresh families (sessions.ts, auth-jwt.ts)               │
 │ authZ: requirePermission / requireRole (permissions.ts, 24 permissions, 3 roles)                          │
 │ tenancy: token → membership → tenant_id; tenant-query-guard test forbids unscoped SQL                    │
 │ WebSocket /ws/alerts (Origin check, cookie only, per-user/tenant caps, re-validation, expiry)            │
 │ Ingest: Wazuh webhook (HMAC + timestamp + nonce, per-credential keys) ── integrations/ingest.ts          │ [TB-3: sensors]
 │ Agents API /agent/v1 (packages/agent-identity: 15-min tokens, firewall, skills, kill switch)             │ [TB-4: AI agents]
 │ LLM explain / copilot (ai.ts, ai-safety.ts): output sanitised, no tools, pseudonymised in strict mode     │ [TB-5: LLM provider]
 │ SOC core: policy → approval → action (shadow/simulation only; live refused in API, engine, DB CHECK)     │
 │ Worker: soc_jobs lease + fencing, retention, reconciler, outbox (in the same process)                    │
 │ Billing: Paddle checkout / webhook (signed)                                                               │ [TB-6: payment provider]
 └──────────────┬──────────────────────────────┬───────────────────────────────────────────────────────────┘
                ▼                              ▼
     PostgreSQL 16 (one DB, all tenants)     Redis (rate limits, realtime fan-out)                [TB-7: data plane]
     app-enforced isolation; RLS only on agent tables for the agent role
```

**Security-critical paths:** sign-in/MFA/refresh; `requirePermission` on every route; `tenant_id` derivation
(token → membership, never request); webhook signature + replay; agent token + firewall; policy/approval digest
binding; audit chains; secret sealing (`LEGION_ENCRYPTION_KEYS`); the database role the API holds.

**Deployment modes:**

| Mode | File | API's DB role |
|---|---|---|
| Default Docker (install.sh, start-docker.ps1, DOCKER-WINDOWS.md) | `docker-compose.yml` | **Postgres bootstrap superuser** (F-01) |
| Production overlay | `+ docker-compose.prod.yml` (`NODE_ENV=production`) | refuses to start as superuser unless `DB_ALLOW_PRIVILEGED_ROLE=true` |
| Pilot | `docker-compose.pilot.yml` | `legion_app` (least privilege, provisioned) — **but owns its tables** (F-02) |
| Bare metal (`npm run setup`) | `server/scripts/setup.mjs` | non-superuser that owns the database (F-02) |

---

## 2. Prioritized findings (evidence = file:line in this branch)

Severity: **Critical** (exploitable now, cross-tenant or full compromise) · **High** · **Medium** · **Low**.
No Critical finding was confirmed.

| ID | Sev | Finding | Evidence | Impact |
|---|---|---|---|---|
| **F-01** | **High** | The default Docker install runs the API as the Postgres **superuser**; outside `NODE_ENV=production` the boot check only warns | `docker-compose.yml:12-13,47` (`DATABASE_URL` = `POSTGRES_USER`), `server/Dockerfile:14` (NODE_ENV deliberately unset), `server/src/index.ts:2595-2599`, `server/src/db/provision.ts:153` | One SQL injection or leaked `DATABASE_URL` = file read/write and program execution on the DB host (`pg_read_file`, `COPY … PROGRAM`), all databases, all tenants |
| **F-02** | **High** | The runtime role **owns** every table in every mode, and the audit "append-only" guard has a switch the runtime role can flip | `provision.ts:13-15,94-120` (ownership transferred to the app role); `db/schema.sql:682-700` and `db/migrations/0001_policy_engine.sql:9-16` (`legion.audit_erasure` GUC); `retention.ts`, `tenant-deletion.ts` set it | A compromised API can `DISABLE TRIGGER`, `TRUNCATE`, `ALTER`, or simply set the erasure switch and delete audit rows. Plain `audit_log` is not keyed; SOC chain is keyed, and Task 15 off-host checkpoints only **detect** this |
| **F-03** | **High** | Payment beneficiary hashing key falls back to a **constant** and is coupled to the webhook secret | `server/src/payments.ts:80` and `:181` — `createHmac("sha256", config.webhookSecret \|\| "legion-payments")` | With no `SECURITY_EVENT_WEBHOOK_SECRET` the key is public → bank accounts (low entropy) can be recovered from a DB dump by brute force. Rotating the webhook secret silently changes every hash → known beneficiaries look new; fraud "repeat" signals reset |
| **F-04** | **High** | No PostgreSQL row-level security on Legion's tenant tables; isolation is application-only | grep: `ROW LEVEL SECURITY` exists only in `packages/agent-identity/src/database/least-privilege.ts` (agent role); `TENANT-ISOLATION.md`; `tests/tenant-query-guard.test.ts` | A single missing `tenant_id` predicate in a future change = cross-tenant read/write. Today: guarded by a recursive static test + sweeps (strong, but one layer) |
| F-05 | Low (re-rated) | Alert ids are derived with the (deprecated) webhook secret | `server/src/integrations/ingest.ts:22`; `server/scripts/setup.mjs` marks `SECURITY_EVENT_WEBHOOK_SECRET` as deprecated, kept only so ids stay stable | It authenticates nothing any more, so there is no reason to rotate it; changing the formula would itself duplicate alerts. **Decision: no code change**; documented: do not change this value |
| **F-06** | Medium | `SOC_AUDIT_KEY` is optional (derived from `JWT_SECRET`) and has **no rotation** | `server/src/audit/events.ts:41-42`, `config.ts:326`; PILOT.md §6 "do not rotate" | Rotating `JWT_SECRET` (a normal action) changes the audit key → audited actions fail closed (availability). A leaked audit key cannot be replaced |
| **F-07** | Medium | CI has no SAST, no secret scanning, no SBOM; the `docker` (install.sh) job is **not** required by the release gate; the default-stack images are unpinned and unscanned | `.github/workflows/ci.yml` jobs list; release-gate `needs` at `ci.yml:499` lacks `docker`; `docker-compose.yml:10,30` (`postgres:16-alpine`, `redis:7-alpine`) | Leaked keys or a vulnerable default-install image would not fail CI. The gosu CRITICAL (CVE-2025-68121) found in the pilot Postgres image almost certainly exists in the default install's Postgres too |
| F-08 | Resolved | Image scan job works and is green for the pilot stack (gosu CRITICAL removed, Postgres non-root, no caps) | run 42230208099 @ 9b9c56c: image-scan, pilot-stack, app (incl. DoS), security, Release gate all success | Covered; the default stack remains F-07 |
| **F-09** | Medium | Incident lifecycle is unconstrained: any status → any status, no `acknowledged_at` / `resolved_at` / `resolved_by`, no reason on reopen | `server/src/index.ts:1395-1403`; `db/schema.sql:118-119` | No MTTA/MTTR, SLA reports measure only open age; reopen/resolve churn is invisible except in the plain audit log |
| **F-10** | Medium | `main` is 42 commits behind; it lacks the SOC core and every fix since 2026-11-04 | `git log origin/main..HEAD` | Anyone deploying `main` gets an older, weaker product |
| F-11 | Low | MITRE ATT&CK comes only from Wazuh rules; Legion's own detections mostly carry no technique (only `credential_attack` → T1110) | `server/src/campaigns.ts:113-236`, `integrations/wazuh.ts:74` | Weaker reporting / coverage view; no security impact |
| F-12 | Low | No hallucination regression tests (model output referring to IPs, hosts or ids that are not in the alert) | `server/tests/ai-*.test.ts` — none matches | Explanations are data-only and sanitised, but a wrong address in a "look here first" line can mislead an analyst |
| F-13 | Low | Worker, API and retention run in one process | `server/src/index.ts` (startRuntime, prune timer) | Availability coupling only (Task 13 R-8) |

**Reviewed and found sound (no finding; regression tests exist):**

| Area | Evidence |
|---|---|
| Route authN/authZ | `tests/route-auth-sweep.test.ts` (every route without a token; viewer cannot mutate), `authorization-hardening`, `auth-hardening`, `mfa`, `session-token-hardening` |
| IDOR / tenant isolation in SQL | recursive `tenant-query-guard` (no unscoped statement on tenant tables; alerts/assets/audit have **no** exceptions), `tenant-isolation-sweep`, `cross-tenant-attacks` |
| WebSocket | `index.ts:2530-2570`: Origin allow-list, cookie-only (no `?token=`), per-user/tenant caps, tenant from the user record, lifetime ≤ token, re-validation, `maxPayload` 16 KB; tests `ws-session-lifetime`, `realtime-recovery` |
| Wazuh ingestion | HMAC + timestamp + nonce, per-credential keys, region refusal, NUL stripping, idempotent insert; `webhook-auth`, `webhook-constant-time`, Wazuh script CI job |
| Job durability / duplicate execution | lease + fencing, compare-and-set `queued→running`, idempotency keys, crash tests (`e2e-soc-resilience`, CI SIGKILL step) |
| AI | LLM has **no tools**; output sanitised (`sanitizeModelOutput`), injection signals flagged; LLM-origin proposals floored to `REQUIRE_APPROVAL` (`policy/evaluate.ts:105`); agents bounded by firewall + server-side permission per skill; R4 = 2 people + MFA; live execution impossible |

---

## 3. Status against the requested phases

| # | Request | Today | Plan item |
|---|---|---|---|
| 2.1 | Separate bootstrap/admin from runtime credentials | Pilot: yes. **Default Docker: no (F-01)** | PR-1 |
| 2.2 | Runtime role without SUPERUSER/CREATEDB/CREATEROLE/REPLICATION/BYPASSRLS | Pilot: yes (asserted in CI). Default: no | PR-1 |
| 2.3 | Least privilege in every mode | Owner role everywhere (F-02) | PR-2 |
| 2.4 | RLS for tenant data | Missing (F-04) | PR-3 |
| 2.5 | Mandatory `PAYMENT_HASH_KEY` | Missing; constant fallback (F-03) | PR-4 |
| 2.6 | Route audit (authN/authZ/IDOR/tenant) | Strong; IDOR sweep is per-resource, not generated from the route table | PR-7 |
| 2.7 | WebSocket | Sound | (test added in PR-7) |
| 2.8 | Audit integrity + secret rotation | SOC chain keyed + off-host checkpoints; plain log not keyed; no audit-key rotation (F-02, F-06) | PR-2, PR-6 |
| 3.1–3.2 | Fix image scan; scan exact local images | Done and green for the pilot (run 42230208099); default stack not scanned (F-07) | PR-10a |
| 3.3 | SBOM + dependency scan | npm audit gate yes; SBOM no | PR-10b |
| 3.4 | Secret scanning + SAST | No | PR-10c/d |
| 3.5 | Pin production images by digest | Pilot + monitoring: yes; default stack: no | PR-10a |
| 3.6–3.7 | Every security check mandatory; no silent bypass | Gate + self-test exist; `docker` job not required | PR-10e |
| 4.1–4.2 | Wazuh normalisation, correlation, dedup | Sound; dedup key coupled to webhook secret (F-05) | PR-5 |
| 4.3 | MITRE where evidence supports it | Partial (F-11) | PR-9 |
| 4.4 | Incident lifecycle | Unconstrained (F-09) | PR-8 |
| 4.5–4.6 | Crash-safe jobs, no duplicates, no cross-tenant leakage | Sound (tested) | — |
| 5.1–5.5 | Untrusted input, no tool grants from prompts, server-side authZ, human approval, evidence | Sound | — |
| 5.6 | Hallucination + tool-abuse regression tests | Tool abuse: yes. Hallucination: no (F-12) | PR-11 |

---

## 4. Implementation plan — small, independently reviewable PRs

Each PR: one concern, regression tests that fail before the fix, CI green including the release gate, docs updated,
no live security action enabled, no security test weakened, backward-compatible migration path stated.

| PR | Fixes | Change | Tests (must fail before) | Compat | Size |
|---|---|---|---|---|---|
| **PR-1** | F-01 | Default `docker-compose.yml` gets the one-shot `db-provision` service; `install.sh` / `start-docker.ps1` generate `APP_DB_PASSWORD`; backend `DATABASE_URL` uses `legion_app`; explicit env list (no admin password in the API); boot **refuses** a privileged role in every mode unless `DB_ALLOW_PRIVILEGED_ROLE=true` (logged loudly). Postgres/Redis pinned by digest and the gosu-free image reused | CI `docker` job asserts role attributes and that `pg_read_file` / `COPY PROGRAM` / `CREATE ROLE` are denied; unit test for the boot decision in non-production | Existing installs: `install.sh` re-run provisions the role and transfers ownership (already supported by provision-cli) | M |
| **PR-2** | F-02 | Migrator/runtime split: `legion_owner` (NOLOGIN) owns the schema; migrations run by `db-provision` as owner; `legion_app` gets DML grants only (+ default privileges). Erasure moves from the GUC to `SECURITY DEFINER` functions owned by `legion_owner` with bounded semantics (retention: only rows older than a floor; tenant deletion: only a tenant with a recorded deletion request). The GUC stops working for the runtime role | runtime role cannot `ALTER`, `DISABLE TRIGGER`, `TRUNCATE`, `DROP`, set the erasure switch, or delete recent audit rows; retention and tenant deletion still pass their existing suites | Opt-in flag first, default after one release; provision-cli migrates ownership | L |
| **PR-3** | F-04 | RLS on every tenant table: `ENABLE` + `FORCE ROW LEVEL SECURITY`, policy `tenant_id = current_setting('legion.tenant_id')::uuid`; the pool sets it per transaction from an AsyncLocalStorage request context; workers set it per workspace (they already work per workspace). Rolled out table group by table group (SOC tables → alerts/assets → identity/billing) | for each table: a query with the wrong tenant context returns 0 rows / fails to write **even when the SQL forgets `tenant_id`**; a query with no context fails closed; existing suites unchanged | Behind `DB_RLS=enforce\|off`; CI runs enforce | L |
| **PR-4** | F-03 | `PAYMENT_HASH_KEY` (≥32 random bytes) mandatory in production (config refuses to start), never the webhook secret, no constant fallback; `PAYMENT_HASH_PREVIOUS_KEYS` so existing hashes still match; `hash_key_id` column; new rows use the new key | config-safety: production without the key refuses; a hash with the old key still matches; changing the webhook secret no longer changes payment matching | Existing installs: set the key = the value currently in use, then rotate | S |
| **PR-5** | F-05 | Alert-id derivation decoupled from the webhook secret (stable per-deployment `ALERT_ID_SALT`, generated by install/preflight); legacy id checked first so no duplicate on upgrade | rotating `SECURITY_EVENT_WEBHOOK_SECRET` does not duplicate an already-ingested event; upgrade path test | Legacy-id lookup kept for one retention period | S |
| **PR-6** | F-06 | `SOC_AUDIT_KEY` mandatory in production; keyring (`SOC_AUDIT_KEYS=k2:…,k1:…`): new events signed with the first key, verification accepts every listed key by `key_id`; rotation writes a `controls.key_rotated` event signed by both | rotation keeps the whole chain verifiable; unknown key id fails; production without the key refuses | Derived-key installs: one-time export of the derived key as `k1` | M |
| **PR-7** | 2.6/2.7 | Generated IDOR sweep: for every route with a path parameter, create the resource in workspace A and call it as workspace B → must be 404 (never 200/403 with data); WebSocket: a second workspace receives none of A's frames across instances | the sweep itself; a deliberately broken route in a fixture proves it catches one | test-only | M |
| **PR-8** | F-09 | Lifecycle table (`open→investigating→resolved`, reopen needs a reason), `acknowledged_at`, `resolved_at`, `resolved_by` (migration 0008), audit + MTTA/MTTR in `response_sla_review` | illegal transitions 422; timestamps set once; reopen without reason 422 | Existing alerts: timestamps null (stated) | S |
| **PR-9** | F-11 | MITRE for Legion's own detections only where the rule proves the technique (e.g. `credential_attack` T1110, `account_compromise` T1078, `wide_sweep` T1046, `data_exfiltration` T1041/T1048) with the evidence rule documented | mapping table test; no technique invented for weak evidence | additive | S |
| **PR-10** | F-07, F-08 | (a) finish image scan; scan default + monitoring stacks; pin default stack digests; (b) SBOM (CycloneDX via syft, pinned + checksum) per image as artifact; (c) secret scanning (gitleaks, pinned + checksum, full history + PR diff, reviewed allow-list); (d) SAST (CodeQL if the repo plan allows, else Semgrep pinned); (e) `docker`, `sbom`, `secrets`, `sast` required by the release gate; `check-ci-gate.mjs` + self-test refuse removal or `continue-on-error` | the gate self-test proves each job cannot be dropped silently; a planted fake secret in a fixture branch fails | CI only | M |
| **PR-11** | F-12 | Hallucination guard: addresses/hosts/ids in model output that do not appear in the alert are flagged and marked; regression tests for it and for tool-abuse paths (agent without permission, forged skill input, injected "approve" text) | the tests | additive | S |
| **PR-12** | — | Docs: INSTALL, RECOVERY, PILOT, SOC-CORE, PRODUCTION-READINESS-ASSESSMENT; remaining-risk register | doc checks in CI where they exist | — | S |

**Suggested order:** PR-10a (unblocks a green gate) → PR-4 → PR-5 → PR-1 → PR-6 → PR-8 → PR-7 → PR-10b–e → PR-2 → PR-3 → PR-9 → PR-11 → PR-12.
Small and independent first; PR-2 and PR-3 change how every query reaches the database and need the most review.

---

## 5. Remaining-risk register (after the plan, if approved)

| Risk | Why it remains | Owner action |
|---|---|---|
| No independent penetration test | Not something code can supply | Book an external test before limited production |
| No HA / single instance (Task 13 K-5) | Infrastructure decision | Managed Postgres + WAL archiving before expansion |
| RLS defends against a forgotten predicate, not against a compromised migrator role | By design | Keep the migrator password only in the provision step |
| Off-host audit checkpoint depends on log shipping being configured | Operator task | Ship container logs off the host (PILOT.md §9.4) |
| SAST/secret-scan false negatives | Tool limits | Keep code review mandatory |
| `main` divergence (F-10) | Merge is the user's decision | Review and merge PR #19 (or successors) |
| RLS covers the first table group only, off by default (PR-3b/c open) | Identity, billing and credential lookups precede the workspace | Design per-lookup system scopes; then turn `DB_RLS=enforce` on for the pilot |
| The API's role can erase a whole workspace through `legion_erase_tenant`, and may pass `force` past a legal hold | Auto-delete and the operator CLI run as that role | Move forced erasure to a separate operator role, or require an out-of-band confirmation |

---

## 6. Decisions needed before implementation

1. **Approve the plan and order** in §4 (or reorder).
2. **PR-2 erasure model:** may retention and tenant deletion move to `SECURITY DEFINER` functions with a minimum age floor (proposal: 30 days for audit rows), so the runtime role can never delete recent audit evidence?
3. **PR-3 RLS rollout:** feature flag (`DB_RLS`) with CI enforcing, table groups in three PRs — acceptable?
4. **PR-10d SAST:** is GitHub Advanced Security / CodeQL available for this repository? If not, Semgrep (pinned) is the fallback.
5. **PR-4/PR-6 upgrade path:** for existing installs, accept "set the new key to the value in use today, then rotate"?
6. **Branch:** keep working on `claude/laughing-clarke-cmfudk` (one PR per item from it), or start the PRs from `main` after PR #19 is merged?
