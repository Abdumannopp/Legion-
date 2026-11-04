# Task 11 — Full system integration and end-to-end simulation

**Scope:** simulation only. Mock connectors, an isolated test database, no production side effects, no deployment, no autonomous production actions. Every test also asserts that nothing real changed (no `ip_blocks` row, no alert status change, no payment resolution).

**Result:** the pipeline works end to end and held under every failure and attack in the brief. Crash testing found **one defect, now fixed** (an action left `running` forever when a worker died mid-simulation). Integration also exposed **seven gaps**, listed below with a remediation plan. None is a security hole in the current simulation-only state; two become important before any live execution.

## 1. What was run

| Suite | Tests | Result |
|---|---|---|
| `tests/e2e-soc-scenario.test.ts` — main scenario, all autonomy modes, automatic path | 10 | pass |
| `tests/e2e-soc-resilience.test.ts` — denial, expiry/replay, duplicates, crashes, LLM failure, injection, conflicts, kill switch, isolation | 33 | pass |
| `tests/e2e-soc-performance.test.ts` — measurements | 5 | pass |
| Server security suite (`npm run test:security`, now includes the two suites above) | 957 | pass |
| Full server suite | 1366 (75 files) | pass |
| `packages/agent-identity` | 917 | pass |
| Typecheck, build, CI-gate script | — | pass |

Harness: `tests/helpers/soc-conductor.ts` (plays the five agents through Legion's **real** interfaces) and `tests/helpers/soc-env.ts`. Wazuh events go through the real signed webhook; agents use their own least-privilege tokens and assigned skills; the policy, approval, action, runtime and audit engines are the production code. Mocked: connectors (previews only) and the LLM provider (stubbed `fetch`).

## 2. Workflow execution trace (ASSIST mode, one run)

Raw data: `e2e-results/trace-main-assist.json`. Attack: scan → 4× brute force → command execution from `45.155.205.12`, plus a log4j finding on the host.

| # | Actor | Step | ms | Result |
|---|---|---|---|---|
| 1 | Legion | wazuh event stored as alert | 0.6 | SEC-B8E746222DFC3B2D [critical] Suspicious command execution after login |
| 2 | Sentinel | threat_detection | 122.3 | 1 finding(s); top patterns ["privilege_use","mitre:T1059"] |
| 3 | Hunter | attack_investigation | 70.4 | 7 event(s), 1 chain(s) |
| 4 | Guardian | vulnerability_analysis | 69.6 | 1 vulnerability finding(s); evidence findings |
| 5 | Guardian | exposure_review | 73.9 | 1 asset(s) ranked |
| 6 | Oracle | alert_analysis | 69.8 | severity critical; critical alert "Suspicious command execution after login" on asset web |
| 7 | Vanguard | containment_candidates | 50.4 | 1 candidate(s); cannot-block 0 |
| 8 | Vanguard | propose ip.block | 15.3 | awaiting_approval (policy REQUIRE_APPROVAL, simulation) |
| 9 | Human | approve (digest-bound) | 51.7 | approved by admin@a.io; action now simulated |
| 10 | Legion | verify result | 3.9 | status simulated; real blocks 0; transitions awaiting_approval>queued>running>simulated; audit  |

Evidence each agent produced: Sentinel score 100, patterns `privilege_use`, `mitre:T1059`. Hunter: 7 events, 1 chain (reconnaissance → credential_access → execution). Guardian: 1 vulnerability finding. Oracle: critical. Vanguard: candidate with 4 attack stages. Agents disagreed slightly (`oracle=critical hunter=high sentinel=high`); the harness took the highest. The policy engine returned `REQUIRE_APPROVAL` (R3 block proposed by an agent); a person approved the exact digest; the action was simulated (`side_effects: none`). Audit trail: `policy.activated → approval.requested → action.awaiting_approval → approval.approve → action.queued → action.running → action.simulated`, chain valid; 24 agent-side skill-call audit rows.

## 3. Requirement by requirement

| Requirement | Evidence | Result |
|---|---|---|
| Mock connectors, isolated env, no side effects | every test compares blocks/alerts/payments before and after; mock Entra connection gives previews only | pass |
| All autonomy modes | D0, OBSERVE → recorded; ASSIST → approval; AUTONOMOUS → R1 runs, **R3 still needs approval**; shadow execution mode → recorded, no approval; `live` refused (API, engine, DB CHECK) | pass |
| Tenant isolation | two workspaces, same attacker, concurrent: each Hunter sees only its 7 events; cross-tenant approval/action/audit reads → 404; B's agent cannot read A's alert; one worker pass leaves each workspace's actions in its own; separate valid audit chains | pass |
| Policy denial | DENY rule → `denied`, no approval, no job, matched rule and explanation recorded; no approval id to abuse | pass |
| Approval expiry and replay | expired → 410 and action `expired`; approved-but-unused-then-expired → `expired`; replay of the same decision, a digest from another action, a second consume, a re-proposal with the same key → all refused or no-ops; self-approval refused; agent tokens cannot approve, propose, change policy or pause | pass |
| Duplicate action prevention | 5 parallel identical investigations → 1 action, 1 approval; 3 parallel workflow triggers → 1 run; 30 actions × 5 workers → each simulated exactly once | pass (see G-01) |
| Worker crashes and recovery | killed after claim → lease expiry → another worker finishes once (14 ms); **killed mid-simulation → was stuck, fixed**; poison job → backoff → dead-letter + audit, other work unaffected | pass after fix |
| LLM provider failures | HTTP 500, 429, network error, garbage body, empty choices: explanations fall back to Legion's own text (labelled not-AI), copilot answers, **the investigation is unaffected** (it uses no model); circuit breaker opens and stops calling the provider; `narrative: true` degrades gracefully | pass |
| Malicious prompt injection | log text ordering `payment.release`, resolve all, disable CEO account, block 8.8.8.8: the only action is `ip.block` of the structured source address, still needs approval; `ai_manipulation` campaign raised; a model that *obeys* the injection only produces stored text — no action, job or state change; LLM-origin proposals need approval even under AUTONOMOUS + allow-all; unknown actions and wrong-agent proposals refused | pass |
| Conflicting agent findings | low-severity alert inside a heavy attack → conflict recorded, higher risk wins, person decides; agents agree on danger but source is a private address → no block proposed | pass in harness (see G-03) |
| Kill switch | pause mid-flow: approved action held, new proposals 423, jobs deferred without spending attempts, resume completes it once; suspending one agent stops it at once while others continue; global DENY policy as a second switch, rollback restores | pass (see G-05) |

## 4. Failure and recovery results

| Failure | Behaviour | Recovery time |
|---|---|---|
| Worker dies after claiming a job | lease holds, nobody else runs it; after lease expiry the next worker runs it exactly once | 14 ms after expiry (lease is 120 s in production) |
| Worker dies mid-simulation | **before fix:** action stayed `running` forever (job handler skipped it). **After fix:** a `running` action idle > 300 s is reclaimed, event `recovered after a worker stopped` | next worker pass after 300 s |
| Poison job | retried with backoff (15 s doubling), dead after max attempts, audited | n/a |
| Approval left to expire | no execution; action ends `expired` | on next read (see G-05) |
| LLM down | local fallback, breaker opens, SOC pipeline unaffected | immediate |

**Defect fixed in this task** (`server/src/actions/engine.ts`, `runtime/worker.ts`): simulations only read, so re-running an abandoned one is safe. Covered by a test that failed before the change.

## 5. Security test results

All of §3 "denial / replay / duplicate / injection / isolation / kill switch" plus: forged or unsigned Wazuh events create no alert; `live` mode rejected at three layers; critical (R4) action refused without a second factor; agent tokens refused on every human-only route. No security test was weakened; the one tightened guard from Task 10 is unchanged.

## 6. Performance (single process, 4 CPUs, local Postgres; `e2e-results/perf.json`)

| Measure | Result |
|---|---|
| Policy evaluation (100-rule policy) | ~67,000 / s, p99 42 µs |
| Wazuh webhook ingest, sequential | 55 events/s, p50 16 ms, p95 25 ms |
| Wazuh webhook ingest, 5 concurrent writers | 116 events/s |
| Full investigation (5 agents + policy + approval + simulation + verify) | p50 262 ms, p95 410 ms (10 runs) |
| Approval decision incl. moving the action to `simulated` | p50 31 ms |
| Propose an action (validate, policy, record, audit) | p50 7 ms, 134 / s |
| Worker pool (4 workers) draining queued simulations | 163 actions / s |
| 40 concurrent proposals in one workspace (audit chain contention) | 276 / s, no gaps |
| Audit chain verification | ~48,000 events / s (451 events: 9 ms) |

Limits of these numbers: one machine, no network latency, no real LLM, no real connectors, small data volumes. They show no pathological behaviour; they are not capacity planning.

## 7. Missing functionality and gaps found

| ID | Severity | Gap |
|---|---|---|
| G-01 | medium | No dedupe of open proposals by target: two alerts from one IP make two block approvals. |
| G-02 | medium | **Hunter and Guardian are not part of any production workflow.** The orchestrator's `alert_response` uses Oracle, Vanguard and Sentinel steps and derives input from the alert fields; it never calls the agents' skills. The full five-agent investigation exists only in the test harness. |
| G-03 | medium | No component reconciles conflicting agent findings, and the policy engine has no input for confidence or disagreement. |
| G-04 | medium | No case/incident object: what each agent found is not stored with the action or approval, so an approver sees the action summary but not the investigation behind it. |
| G-05 | low–medium | Approval expiry and "approved while paused" are applied lazily (when someone reads or decides). Nothing sweeps them; an approved action in a paused workspace stays `awaiting_approval` until read. |
| G-06 | low | An action whose job exhausts its attempts (poison simulation) stays `running`; jobs abandoned on the last attempt are dead-lettered without an audit event. |
| G-07 | info | "Legion verifies the result" exists only as the harness check: v0 has no executors, so there is no post-action verification step to build yet. Dashboard screens for approvals/actions/audit do not exist. |

Not tested: real LLM provider latency and behaviour, multi-process (multi-host) runtime races (concurrency was tested with parallel workers on separate DB connections in one process), rate limits on `POST /actions`, very large workspaces, and database failover.

## 8. Remediation plan (suggested order)

1. **G-02 + G-04:** make a production `investigation` workflow: Sentinel → Hunter → Guardian → Oracle → Vanguard through the real skills, storing their findings in a case record linked to the action and shown to the approver. Prerequisite for any dashboard work.
2. **G-05 + G-06:** a periodic reconciler (runtime job) that expires approvals, resumes approved actions after a pause, fails actions whose job is dead, and audits abandoned dead-letters.
3. **G-01:** open-proposal dedupe by `(workspace, action, target)` with a clear "already pending" answer.
4. **G-03:** add `confidence` and `conflict` to the policy request (code-supplied, never model-supplied) so a policy can require approval when agents disagree.
5. Dashboard screens: approval queue with investigation evidence, action history, kill switch, `GET /soc/metrics`.
6. Run shadow mode against real traffic and review `shadow.divergent` before designing any live execution (carry-over from Task 10).
7. Load, rate-limit and multi-host tests once a staging environment exists.

## 9. Files

New: `server/tests/e2e-soc-{scenario,resilience,performance}.test.ts`, `server/tests/helpers/soc-{conductor,env}.ts`, `e2e-results/*.json`, this report. Changed: `server/src/actions/engine.ts` and `server/src/runtime/worker.ts` (crash-recovery fix), `server/package.json` (two suites added to `test:security`).
