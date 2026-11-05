# Legion — Production readiness assessment (Task 13)

Prepared by: Claude (acting as Principal SRE / Security Engineer / Release Manager)
Commit assessed: see §3 (the exact SHA and the CI run that tested it)
Nothing in this document was deployed. No listener was opened, no real action was enabled.

## 0. Verdict (read this first)

| Question | Answer |
|---|---|
| Is Legion ready for **general production** (many customer tenants, real money/data, 24×7 expectations)? | **NO-GO** |
| Is Legion ready for the **controlled pilot** described in `PILOT.md` (one workspace, simulation only)? | **GO, conditional** on the approvals in §10 and the items marked *before pilot* in §12 |
| Is Legion ready for **autonomous (live) actions**? | **NO. Not built, not tested, and refused in three places by design.** |

Why general production is a NO-GO — the blockers, each of them a missing *evidence*, not a missing opinion:

1. **No soak data.** Everything measured so far was measured in short CI runs and a rehearsal on a tiny dataset. There has been no 14-day run of the pilot stack (`PILOT.md` §12.3), so availability, alert delivery to a human, and the real RTO on a real dataset are unmeasured.
2. **Security sign-off is not signed.** The sheet in §6 is complete with evidence, but no human has signed it, and there has been **no independent penetration test**. My own attack assessment is not independent.
3. **The audit trail can be disabled by a compromised API** (R-3): the application database role owns its tables. The keyed SOC chain makes tampering *detectable*, but the plain `audit_log` is not keyed.
4. **No retention for SOC history** (measured ≈ 6.5 KB per action, unbounded; the new hourly action budget caps the rate, not the total).
5. **No HA.** One API process (also running the worker), one Postgres, one Redis. A host loss is a restore from the nightly backup (RPO up to 24 h).
6. **No approval/action/policy screens** in the dashboard (R-5). Approvers use the API.
7. **The alert path to a human has never been exercised** against a real Alertmanager receiver (rules are unit-tested with `promtool`; delivery is not).

None of these is a design flaw; they are the work that a pilot is meant to produce evidence for. The rollout in §8 is ordered so that each stage closes some of them before the next begins.

## 1. How to read the evidence

| Mark | Meaning |
|---|---|
| ✅ CI | Passed in GitHub Actions on the assessed commit (a required job of the release gate) |
| ✅ local | I ran it in this environment; reproducible with the command given |
| 🟡 | Tested only partially, or in a rehearsal rather than in the target environment |
| ❌ | Not tested / not true / not built |

"Pass" means the command exited 0 with the stated counts. Nothing here is claimed from reading code alone unless marked *(by reading)*.

## 2. The fourteen requirements

| # | Requirement | Status | Evidence | Gap |
|---|---|---|---|---|
| 1 | All required CI checks pass | ✅ CI (see §3) | Release gate requires: deploy-scripts, dependencies, agent-identity, app, security-assessment, **pilot-stack** (added in this task). `ops/tests/test-ci-gate.sh` (14 checks) proves the gate cannot be switched off quietly | Branch protection on the repository must mark **Release gate** as required (GitHub setting; I cannot verify it) |
| 2 | Security tests pass | ✅ local + CI | `npm run test:security`: **53 files, 1006 tests pass**. The same suite runs in CI job "Security tests and attack assessment", plus the black-box production-mode probe and the DoS job | Tests are mine/the team's, not independent |
| 3 | No unresolved critical vulnerabilities | 🟡 | `npm audit --audit-level=high`: 0 (CI "Known vulnerabilities in the lockfile" and "Agent identity" jobs). Attack assessment verdicts validated by `validate-assessment` | Dependency scanning covers known advisories only. No container-image scan (Trivy/Grype) is run; base images are pinned by tag, not digest (R-2) |
| 4 | Tenant isolation verified | ✅ CI + local | `tenant-isolation-sweep`, `cross-tenant-attacks`, recursive `tenant-query-guard`; live rehearsal: second workspace got 404 on 9/9 cross-tenant probes, empty audit/policy views | Application-enforced only; **no Postgres row-level security** (R-4) |
| 5 | Authentication and authorization secure | ✅ CI + local | `auth-hardening`, `session-token-hardening`, `authorization-hardening`, `mfa`, `first-admin` tests; **new** `route-auth-sweep.test.ts` (7 tests): every route of the real app is called without a token (must be 401 or a reviewed public route) and as a VIEWER (must not mutate) | Sweep enumerates direct app routes; mounted agent routers are tested by prefix. No external review |
| 6 | Approval and policy enforcement correct | ✅ CI | `policy-engine`, `approval-engine`, `action-engine`, `orchestrator` tests; E2E suites (`e2e-soc-scenario`, `e2e-soc-resilience`): approvals are digest-bound, R4 needs 2 approvers + MFA, a changed action invalidates the approval, the policy engine runs enforced on the Action Engine path | Policy runs in **shadow** on the legacy paths (by design for the pilot) |
| 7 | Action execution restricted | ✅ CI + local + pilot stack | Live mode is refused in the API, in the engine and by a database CHECK constraint. Pilot stack in CI asserts `legion_soc_actions_live 0` on `/metrics`. Hourly per-workspace budget `SOC_ACTIONS_PER_HOUR` (default 3000, test proves 429) | There is no live executor at all. That is the restriction, and also the reason §9 stage 5 is not startable |
| 8 | Kill switch tested | ✅ local + CI | Level 1 (`/actions/controls`), 2 (agent suspend), 3 (policy freeze + rollback), 4 (env flags) rehearsed in Tasks 11/12 and covered by tests. Level 5 (`stop backend`) | Level 5 and "Wazuh buffering while the backend is stopped" were not rehearsed |
| 9 | Backup restoration verified | ✅ CI + local 🟡 | CI job "Backup, verify and restore against real Postgres"; rehearsal: backup 1.1 s, restore RTO 2.0 s, audit chain of 245 events valid after restore with the same key, wrong key fails closed | Tiny dataset. RTO on a real dataset unknown. Off-host upload and a real `age` key custody were not exercised |
| 10 | Monitoring and alerting operational | ✅ CI 🟡 | `promtool check rules` + `promtool test rules` (22 rules, unit-tested firing and not-firing cases) in CI; every metric named by a rule or dashboard panel is proven to exist; the pilot stack in CI serves `/metrics` behind a token; **new** HTTP request/error/latency metrics and alerts | No real Alertmanager → human delivery test (`PILOT.md` §9.3, Gate C). Dashboards were never rendered in a live Grafana |
| 11 | Worker recovery works | ✅ local + CI | Rehearsal: `kill -9` with 60 concurrent actions → all 60 simulated exactly once, 0 duplicates, 0 dead jobs, chain valid, recovery 66 s. CI pilot-stack step *Crash and recovery* kills the container's main process from the host and requires an automatic restart to healthy (see §3 for its history) | Recovery of in-flight simulations takes up to ~75 s (R-11) |
| 12 | Rate limits and resource budgets enforced | ✅ CI + local | **New** `rate-limits-and-budgets.test.ts`: sign-in flood is limited (429) with the limiter on; action budget returns 429; JSON body cap; payload-size CHECK constraints on SOC tables. CI "DoS resilience" job floods the API behind real nginx. Containers: memory/CPU/pids limits asserted by preflight, `CapEff=0` checked from outside in CI | Container memory limits were not pushed to OOM in CI. Unbounded SOC history growth (retention missing) — measured, documented, not fixed |
| 13 | Audit integrity verified | ✅ CI + local | `soc-audit`, `audit-append-only` tests; keyed HMAC chain, fails closed on key mismatch (alert `LegionAuditKeyMismatch`); `/soc/audit/verify` checked in the pilot stack in CI and after restore | R-3 (owner can disable triggers), R-10 (no key rotation, no automated off-host head checkpoint) |
| 14 | Deployment and rollback tested | 🟡 | Deploy: the pilot stack is built and started from `docker-compose.pilot.yml` in CI (preflight → build → up → health → first-run setup → audit verify). Rollback level A (switches) rehearsed; level C (restore) rehearsed; `install.sh` job | **Rollback level B (previous image) was never executed.** No blue/green or canary mechanism exists. Migrations are forward-only, so level B is only safe for additive migrations |

## 3. CI/CD verification

Exact record of the runs behind this assessment (update the table with the final run before sign-off):

| Commit | Run | Result | Notes |
|---|---|---|---|
| 7abceae (Task 12) | CI green | ✅ | baseline before Task 13 |
| 5cf0273 | run 41969104201 | **Failed: only "Pilot stack" → "Crash and recovery"**. All other jobs green: Typecheck/tests/build (including journeys, production probe, sign-in load, DoS), Agent identity, Security tests and attack assessment, Deploy scripts, dependencies, install.sh | Root cause: my test used `docker kill`, which Docker treats as a *manual stop*; `restart: unless-stopped` correctly does not restart a manually stopped container. Not a stack defect. Found by reading the job log: one backend start, no second. **Note:** the Release gate was green while this job was red because the job was not yet required — a gap in the gate itself |
| d77298e | run 41970573889 / 41970580763 | Crash test rewritten: SIGKILL the container's main PID from the host, require a changed `StartedAt` and `healthy` | Superseded by 27d8ecd run |
| 27d8ecd | **run 41970622523: success (all 7 jobs, Release gate success)** | `pilot-stack` added to the Release gate `needs`, to `REQUIRED_FOR_RELEASE` in `check-ci-gate.mjs`, and to its self-test. Pilot-stack job: every step success, including *Crash and recovery (SIGKILL the API process)* | Verified by reading the job steps and the Release gate conclusion |
| f8e1154 (docs + PILOT.md update) | **run 41970811888: success (all 8 jobs incl. Typecheck/tests/build, DoS resilience, pilot-stack with crash recovery; Release gate success; Release package skipped as expected, not a tag)** | Verified by reading each job's conclusion |

**Still required before sign-off:** branch protection that makes Release gate required (a GitHub setting, not verifiable from here), and the human sign-off in §6. Both CI commits are green on their Release gate.

What CI proves that local runs cannot: real Ubuntu runner, real Docker, real nginx, real browser journeys, `promtool`, `pg_dump`/`age`, shellcheck.

What CI does not run: load beyond the DoS job, long soak, restore of a production-size dump, real TLS termination, a real Wazuh manager, a real SMTP relay, a real AI provider.

## 4. Release checklist

Tick each box only with evidence attached (command output or a link). *Before pilot* items are required for stage 2; *before limited production* for stage 3.

**Code and CI**
- [ ] Head commit equals the commit approved in §10; `git status` clean; tag created from it
- [ ] Release gate green on that commit, including `pilot-stack` (link the run)
- [ ] Branch protection requires **Release gate**; force-push to the release branch disabled
- [ ] `npm audit --audit-level=high` 0 on the lockfile (CI job)
- [ ] Image scan (Trivy/Grype) of both built images: 0 critical — **not yet in CI** (§12 K-3)
- [ ] Base image digests pinned (R-2) — *before pilot*

**Configuration and secrets**
- [ ] `node ops/pilot-preflight.mjs` 0 FAIL on the real `.env` (WARNs recorded in `PILOT.md` §12.2)
- [ ] Each secret generated fresh (`openssl rand -hex 32`), stored in the secret store *and* only there plus `.env` mode 600
- [ ] `LEGION_ENCRYPTION_KEYS` and `SOC_AUDIT_KEY` copies held in a **separate** store from the backups
- [ ] `FRONTEND_URL`, `CORS_ORIGINS`, `TRUSTED_PROXIES` exact; `COOKIE_SECURE=true`

**Data**
- [ ] Pre-deploy backup taken, checksum recorded, restore into a scratch DB succeeded, chain verified
- [ ] Off-host copy exists and its age private key is held by two people
- [ ] Restore drill timed on a production-sized dataset (RTO written down)

**Network and edge**
- [ ] `ss -ltn`: only 22/80/443 externally; API/dashboard on loopback; 5432/6379 absent
- [ ] TLS: `testssl.sh` no MEDIUM or worse; HSTS present; certificate expiry alert exists
- [ ] Webhook endpoint restricted to the sensor's address at nginx

**Operations**
- [ ] Alert-path test (`PILOT.md` §9.3) received by a human, both fire and resolve
- [ ] On-call rota and escalation named (§7)
- [ ] Runbooks reachable without the system being up (printed or in a separate wiki)
- [ ] Kill-switch drill performed by the on-call person, not only by the author
- [ ] Previous image kept; **rollback level B rehearsed once** — *before pilot*

**Safety (re-check on every deploy)**
- [ ] `/metrics`: `legion_soc_actions_live 0`; `POLICY_ENGINE_MODE=shadow`; `ORCHESTRATOR_AUTO_MODE=shadow`; `SEED_DEMO_DATA=false`
- [ ] `/soc/audit/verify` `ok:true`; chain head recorded off-host

## 5. Known limitations (honest list)

| ID | Limitation | Severity for production | Status |
|---|---|---|---|
| K-1 | Audit-trail tamper resistance depends on the table owner not turning triggers off (R-3) | **High** for multi-tenant | Open. Split migrator/runtime roles; keyed chain mitigates |
| K-2 | No retention/archival for SOC history (≈6.5 KB per action, unbounded) | **High** at scale | Open. Rate-capped only |
| K-3 | No container image vulnerability scan in CI; base images by tag | Medium | Open |
| K-4 | Tenant isolation relies on application code, not Postgres RLS (R-4) | Medium | Open. Heavily tested; one defect = cross-tenant exposure |
| K-5 | Single instance: no HA for API, Postgres, Redis. RPO ≤ 24 h with nightly backups | **High** for a 24×7 promise | Open. WAL archiving / managed Postgres needed for stage 4 |
| K-6 | `SOC_AUDIT_KEY` has no rotation procedure; no automated off-host chain checkpoint (R-10) | Medium | Open |
| K-7 | No dashboard screens for approvals, actions, policy (R-5) | Medium (usability, operator error) | Open |
| K-8 | Approval expiry / "approved while paused" are lazily applied (R-6) | Low | Open |
| K-9 | Only the 3-step alert workflow is wired; Hunter/Guardian workflows are not (R-7) | Low | Open |
| K-10 | No live executor exists. Autonomous actions cannot be enabled, by design | n/a | Blocks stage 5 until designed and reviewed |
| K-11 | Real AI provider and real connector behaviour never tested (none configured) (R-13) | Medium if AI is enabled | Open |
| K-12 | Recovery of in-flight simulations after a hard crash takes up to ~75 s (R-11) | Low | Accepted |
| K-13 | No independent security test; no SOC 2 / ISO evidence; legal items in `LEGAL-QUESTIONS.md` unresolved | **High** for enterprise sales | Open |
| K-14 | Monitoring has never run against a live Prometheus/Grafana/Alertmanager with a real receiver | Medium | Open (Gate C) |
| K-15 | Event-ingest throughput limit not measured at production volume; DoS job covers floods, not sustained legitimate load | Medium | Open |
| K-16 | Rollback by previous image (level B) never executed; migrations are forward-only | Medium | Open — rehearse before pilot |

## 6. Security sign-off

This sheet is **unsigned**. Evidence is attached for each line; the decision belongs to a person who is accountable.

| Area | Evidence | Reviewer (name) | Date | Signed |
|---|---|---|---|---|
| Authentication / sessions / MFA | `auth-hardening`, `session-token-hardening`, `mfa`, `first-admin`, route-auth-sweep | | | ☐ |
| Authorization / least privilege | `authorization-hardening`, route-auth-sweep, DB-role check in CI (`pilot-stack`) | | | ☐ |
| Tenant isolation | `tenant-isolation-sweep`, `cross-tenant-attacks`, `tenant-query-guard`, rehearsal probes | | | ☐ |
| Approval / policy / action restriction | `policy-engine`, `approval-engine`, `action-engine`, E2E suites, DB CHECK on live mode | | | ☐ |
| Audit integrity | `soc-audit`, `audit-append-only`, key-mismatch fail-closed | | | ☐ |
| Secrets handling | `secrets-at-rest`, `secret-placeholders`, preflight | | | ☐ |
| Container and network hardening | `pilot-stack` CI job (uid, read-only, `CapEff=0`, `NoNewPrivs=1`, loopback ports, no egress from data network, no admin password in API) | | | ☐ |
| Dependency vulnerabilities | CI `dependencies`, `npm audit` | | | ☐ |
| **Independent penetration test** | **none** | | | ☐ **required before stage 3** |
| Residual risk acceptance (K-1…K-16) | §5 | | | ☐ |

## 7. Incident response

**Severity**

| Sev | Meaning | Examples | Response |
|---|---|---|---|
| S1 | Safety or confidentiality breach | `LegionLiveActionDetected`; cross-tenant data seen; audit chain broken; secret leaked | Page now; **stop** (kill switch level 4–5); preserve DB and logs; no restarts that destroy evidence |
| S2 | Service down or data at risk | API down > 5 min; backup failed twice; disk > 90 % | Page; restore per `RECOVERY.md` if needed |
| S3 | Degraded | Dead jobs, approvals waiting, elevated 5xx | Ticket, same day |

**First 15 minutes (S1)**
1. Declare the incident, name an incident commander and a scribe (write times).
2. Contain with the lowest kill-switch level that stops the harm (`PILOT.md` §10). Pausing the workspace is reversible and keeps ingest running.
3. Preserve: `ops/backup.sh` snapshot, copy of container logs, `GET /soc/audit` head and `verify` output.
4. Do not delete rows, do not edit an applied migration, do not rotate `SOC_AUDIT_KEY` (no procedure exists) without the commander's decision.
5. Decide rollback with §8 table; write the decision and reasoning in the log.
6. Notify: affected customers within the contractual window; for personal data, the supervisory authority within 72 h (legal owner decides).
7. After: blameless review in 5 working days, with a regression test added for any code defect before the incident closes.

**Contacts to fill in before pilot:** on-call primary / secondary, incident commander, legal contact, hosting provider support. *None are named today.*

## 8. Rollback plan and triggers

**Automatic triggers — roll back or stop without waiting for a meeting**

| Trigger | Action |
|---|---|
| `legion_soc_actions_live > 0` | Stop the stack (level 5). Always S1 |
| Cross-workspace data returned by any probe or report | Kill switch + take the stack off the internet (close the listener). S1 |
| `/soc/audit/verify` `ok:false` not explained by a key error | Freeze writes (pause), preserve, S1 |
| Any applied migration refuses to run / checksum mismatch | Do not start; use rollback C or fix forward under review |
| 5xx rate > 2 % for 10 min (alert `LegionHighErrorRate`) or p95 latency > 2 s for 10 min (`LegionSlowResponses`) | Level B (previous image) if it started with a deploy; else investigate |
| Worker stalled > 5 min (`LegionSocJobsBacklog`) after one restart | Level 1 pause, investigate |
| Backup stale > 36 h or restore test failed | Freeze further releases; fix before anything else |
| Error budget: availability < 99.5 % in any rolling 7 days (pilot) | Hold stage promotion |

**Procedures:** `PILOT.md` §11.2 (levels A switches, B previous image, C restore from pre-deploy backup, D disaster recovery). What is *not* yet proven: level B (§5 K-16). Do not promote beyond stage 2 before it has been executed once and timed.

**Decision rights:** the on-call engineer may use levels A and B at any time. Levels C and D, and re-opening a closed listener, need the incident commander and the owner.

## 9. Deployment plan (nothing here has been run)

1. Freeze: tag the approved commit; run the full CI; record the run link.
2. Prepare: preflight on the real `.env`; backup; record checksum; confirm previous image tag present.
3. Deploy with `docker compose --env-file .env.pilot -f docker-compose.pilot.yml up -d` (`db-provision` first, then migrations).
4. Verify: containers healthy; `/metrics`; `legion_soc_actions_live 0`; audit verify; sample alert end to end; alert-path test.
5. Observe for 60 minutes with two people watching the dashboard; only then announce.
6. Record: deployment log entry (who, commit, time, checks).

## 10. Gradual rollout

Each stage has an entry condition (must be true *before*), what runs, and exit criteria (must be true *to leave*). A stage is never skipped. Promotion needs a named approver; this document does not grant it.

| Stage | Scope | Autonomy | Entry conditions | Exit criteria |
|---|---|---|---|---|
| **1. Internal environment** | Own staging host, synthetic data, own people | Simulation only | CI green; checklist §4 *before pilot* items done; level-B rollback rehearsed; alert-path tested; **Gate C of PILOT.md complete** | 7 days with: 0 safety breaches, alerts delivered ≤ 5 min, restore drill on realistic-size data passed, rollback B timed |
| **2. Controlled pilot** | One friendly workspace, real Wazuh feed (read-only) | Shadow + simulation (as `docker-compose.pilot.yml` fixes it) | Stage 1 exit; the four approvals in `PILOT.md` §12.1 recorded; sign-off sheet §6 signed for everything except the pen-test line | `PILOT.md` §12.3 criteria 1–13 met over ≥ 14 days |
| **3. Limited production tenants** | 3–10 named customers, contracts say "beta" | Still no live actions; humans act on recommendations | Stage 2 exit; **independent pen-test with no open high/critical**; migrator/runtime role split (K-1); SOC history retention (K-2); image scan in CI (K-3); approval/action screens (K-7); on-call rota staffed; legal items resolved; Postgres RLS decision (K-4) recorded | 30 days: availability ≥ 99.5 %, 0 isolation findings, 0 S1, incident response exercised once as a game-day |
| **4. Expanded production** | Self-serve signups | Still none | Stage 3 exit; HA / managed Postgres + WAL archiving (K-5); key-rotation procedure (K-6); capacity test at 3× expected load (K-15); SLA drafted | 90 days within SLA; error budget policy in force |
| **5. Carefully controlled autonomy** | One workspace volunteers | **One** low-risk, reversible action (e.g. block an address ≤ 60 min) | Stage 4 exit **plus** all conditions in `PILOT.md` §12.3 "To ask for autonomous actions": reviewed live-executor design, scoped connector credentials, rehearsed rollback of that action, pilot owner signs; a **new** threat model and a **new** attack assessment of the executor; the three refusal points (API, engine, DB CHECK) changed in one reviewed commit with tests that the old refusal now applies to every other action | Per-action evidence: zero unapproved executions, rollback time measured, then widen action by action, never by class |

## 11. Go / no-go recommendation

| Decision | Recommendation | Basis |
|---|---|---|
| Deploy the **pilot stack** to a staging host (stage 1) | **GO** once the owner approves and the *before pilot* items in §4 are done | CI proves the hardened stack builds, starts, is non-root / read-only / capability-free, reaches Redis and Postgres as a least-privilege role, serves `/metrics` and verifies its audit chain, and restarts after a crash |
| Run the **controlled pilot** (stage 2) | **GO, conditional** on stage 1 exit and the approvals in `PILOT.md` §12.1 | Simulation only; every unsafe mode refused three ways; kill switches rehearsed |
| **General production** | **NO-GO** | Blockers 1–7 in §0. Revisit after stage 3 evidence |
| **Autonomous actions** | **NO-GO** | Nothing to enable; requires its own design, review and approval |

## 12. Work that follows from this assessment, in order

*Before pilot (stage 1 entry):* rehearse rollback level B and time it; run `PILOT.md` Gate C including the alert-path test and a restore drill on a realistic dataset; pin image digests (R-2); name on-call and incident contacts; set branch protection to require **Release gate**.
*Before limited production (stage 3):* independent pen-test; migrator/runtime role split; SOC history retention; image vulnerability scan in CI; dashboard screens for approvals/actions/policy; decide RLS.
*Before expansion (stage 4):* HA and point-in-time recovery; audit-key rotation + automated off-host head; load test at production volume.

## 13. Evidence index

CI: GitHub Actions workflow `.github/workflows/ci.yml` (jobs: app, agent-identity, security-assessment, dependencies, deploy-scripts, docker, pilot-stack, release-gate). Gate self-test: `ops/tests/test-ci-gate.sh`.
Tests added in this task: `server/tests/route-auth-sweep.test.ts`, `server/tests/rate-limits-and-budgets.test.ts`, extended `server/tests/metrics.test.ts`; `monitoring/alerts.test.yml` (promtool).
Code changed in this task: action budget (`server/src/actions/engine.ts`, `config.ts`), HTTP metrics (`server/src/http-stats.ts`, `access-log.ts`, `metrics.ts`), pilot stack (Redis protected mode, `/var/lib/legion` ownership), alert rules, Grafana dashboard.
Earlier evidence: `PILOT.md` §14, `E2E-REPORT.md`, `SOC-CORE.md`, `TENANT-ISOLATION.md`.
