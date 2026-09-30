# Legion — AI Agent Security (Phase 4) — 2026-09-30

Branch `claude/laughing-clarke-cmfudk`. Scope: `packages/agent-identity` (the agent
identity / firewall / tool-security module) and its wiring into `server/`.

This phase turns the agent firewall from a three-answer gate (ALLOW / WARN /
BLOCK) into a policy engine whose answers include **human approval**
(CONFIRM) and **containment** (QUARANTINE, KILL), closes the gaps that made
"sensitive action" and "policy evaluated" two different things, adds MCP
tool-poisoning defence, an agent registry, and SOC alerting for agent
security events — and proves, with adversarial tests and the pinned attack
assessment, that policy is evaluated and recorded **before** any sensitive
tool executes.

---

## 1. What changed, by requirement

### Agent identity (already present; verified, one gap closed)

| Requirement | Where | Status |
|---|---|---|
| Unique identity | `machine_identities.id` (uuid), per tenant; credentials → 15-minute tokens (`routes/agent.ts`) | existing |
| Owner / workspace | `owner_user_id`, `tenant_id`; effective permissions = grants ∩ owner's current role, recomputed per request | existing |
| Explicit permissions | `PERMISSION_TIERS`; tier 3 (users, settings, exports, containment) never grantable | existing |
| Lifecycle | `active / suspended / revoked`, expiry; re-read at **every** firewall decision (`liveIdentity`) | existing |
| Revocation | per identity, per credential, kill switch; **new:** the firewall itself can revoke (KILL) | **extended** |

### Agent registry — **new** (`src/registry.ts`, `GET /agents/registry`, `GET /service-accounts/registry`)

Per identity: owner (and whether the owner is still active), lifecycle status
and *whether it can act right now* (and why not), granted vs. effective
permissions, tool families and assigned skills, tools actually used
(window, default 30 days), connected systems (external destinations, MCP
servers, other agents it reached), risk (declared level, the baseline its
permissions imply, behaviour level/score, refusals, containments, pending
approvals, an overall rating used for sorting), and last activity. Computed
from Legion's own records (identities, grants, decision log, behaviour
state, approvals) — never from what an agent reports. People only
(admin/analyst); tenant-scoped.

### Policy engine — decisions ALLOW / WARN / **CONFIRM** / BLOCK / **QUARANTINE** / **KILL**

`firewall/types.ts`, `firewall/engine.ts`, `firewall/policy.ts`

- `DECISIONS` ordered by severity; the strictest rule hit wins.
- **`permits()` is the only way anything decides whether to run.** Every
  former `decision === "BLOCK"` / `!== "BLOCK"` comparison (HTTP guard,
  tool gateway ticket issuance and execution, firewall executors, MCP calls,
  egress, skills runtime, A2A send/act recording, behaviour signals) was
  replaced, so a new decision can never be read as "not blocked".
- Policy `responses` (validated, versioned, audited like the rest of the policy):
  - `confirm.permissions` — **default: every tool permission that acts on the
    world** (`tool.*:write`, `tool.shell:execute`). An agent may hold them but
    never use them without a person approving each action.
  - `confirm.riskAt` — optional risk band that asks instead of warning (default off).
  - `quarantineOn` — default: `tenant.mismatch`, `a2a.cross_tenant`,
    `sql.foreign_tenant`, `a2a.laundering`, `a2a.injection_payload`,
    `a2a.hidden_tool_request`, `egress.secret_in_payload`, `a2a.secret_in_payload`.
  - `killOn` — default: `http.legion_secret` (sending Legion's own credentials out).
- Monitor mode still observes: soft refusals → WARN (`would_block`), and it
  never quarantines or kills; hard rules still refuse; a hard CONFIRM is not waived.
- Order inside `evaluate()`: rules → responses → advisors (can only escalate)
  → approval (consume or request) → **decision recorded (hash chain)** →
  interaction recorded → **containment applied** → host hook → return.
  Unrecordable decision ⇒ BLOCK.

### CONFIRM — human approval of one exact action (`firewall/approvals.ts`, table `agent_action_approvals`)

- Refusal `403 approval_required` with `approval {id, status: pending, expiresAt}`;
  **no tool ticket** is issued, the executor never runs.
- Re-asking for the same action reuses the open request; `maxPendingPerAgent` caps floods.
- **Only people answer**: `GET /firewall/approvals`, `POST /firewall/approvals/:id/approve|deny`.
  Machines cannot reach these routes; only an administrator or the agent's
  owner may answer; nobody may approve a permission their own role lacks;
  answers are audited (`firewall.approval_granted/_denied`) with reason.
- The agent retries with `x-legion-approval-id`. Consumption is one atomic
  `UPDATE … WHERE status='approved' AND expires_at>now() AND identity=… AND
  action_digest=…`. The digest covers the call as sent (for HTTP routes:
  method, path, query and body), the person it acts for and the relayed
  message it cites. Changed argument, other agent, second use, forged id or
  expired approval ⇒ **BLOCK `approval.invalid`**; denied ⇒ `approval.denied`.
- The approval satisfies CONFIRM rules **only**: everything else is
  evaluated again, so a suspension, a revoked permission or new untrusted
  content between approval and retry still stops the action.
- Nested checks of the *same* approved execution (the egress of an approved
  HTTP call, the write of an approved files call) are covered through a
  Legion-internal `ctx.confirmed` that is never read from a request
  (`tools/gateway.ts executionContext`).
- `GET /agent/v1/approvals/:id` lets an agent see only its own request's status.

### QUARANTINE / KILL — containment before the answer

`index.ts` wires `firewall.setResponder` to the kill switch (`killswitch/service.ts activate()`):

- QUARANTINE ⇒ suspended (compromise *suspected*): tokens, unused tool
  tickets, pending A2A requests withdrawn; running executions aborted (here
  immediately, other instances within the watchdog interval); security
  event (hash-chained) + audit + admin notice. Credentials survive so a
  person can resume after review.
- KILL ⇒ the same as a *confirmed* compromise: credentials and people's
  delegations revoked too.
- Awaited **before** the decision is returned; the response carries
  `containment {action, applied}`. If containment fails the action is still
  refused and the SOC alert is raised as **critical** with the failure.

### Agent firewall coverage

Unchanged surfaces (API routes, files, database, egress with DNS-rebinding
re-check, tools, MCP, A2A, analysed tool calls for 10 tool families), now
all behind `permits()`. `/kill-switch/all` gained `includeServiceAccounts`
so an organisation-wide stop can also stop tool servers / MCP bridges
(previous assessment finding KSB-5).

### Prompt injection

Existing: layered classifier, untrusted-content hold (any external content
read ⇒ no state change for 15 min unless reviewed), malicious content
quarantine, tool output treated as untrusted, A2A payload scanning, fenced
prompt assembly. **New for tool definitions** (`firewall/tool-poisoning.ts`):
every MCP call — direct and via the tool gateway — scans the definition the
server advertises (description, parameter names, every description / title /
default / enum in the schema) for secret paths, credential requests,
concealment from the user, hidden `<IMPORTANT>`-style blocks, steering of
other tools, coercion, exfiltration destinations, plus the classifier's
override / persona / invisible-text findings. Malicious ⇒ BLOCK
`mcp.poisoned_definition` **even when the hash was pinned**, and the text is
recorded against the agent as malicious content (so it is held from unsafe
actions until reviewed). Suspicious ⇒ CONFIRM. A definition that does not
match its claimed hash ⇒ BLOCK. `POST /firewall/mcp/inspect` shows admins
the hash, verdict and findings before they pin a tool.

### MCP / A2A

Tool identity = server + name + sha256 of the live definition (computed by
Legion, never trusted from the caller); authorization per tool in policy;
trust boundary = tool output and tool descriptions are untrusted content;
input validation per tool spec (declared args, size, secrets, URL egress);
A2A: allowlisted pairs, no laundering, depth/fan-out/budget limits, hidden
tool delegation detection, authority carried down the chain, append-only
interaction log. New: laundering, injection payloads and hidden structured
tool requests quarantine the sender by default.

### Kill switch

Existing single implementation for every stop path; new callers: the
firewall (QUARANTINE/KILL) and `/kill-switch/all` with service accounts.

### AI Copilot — advisory by default (verified)

`POST /copilot/chat` and `POST /alerts/:id/explain` return text flagged
`advisory: true`; nothing in a model reply is executed (existing
`tests/ai-output-is-data.test.ts` "an obedient model still changes nothing").
Skills pass their model only assembled prompts and are read-only. Agents
that *do* act are machine identities behind the firewall, where state
changes that leave Legion now need a person's approval per action by default.

### SOC visibility — **new** (`server/src/agent-alerts.ts`)

Through the durable outbox pipeline (stored, versioned, emailed, pushed),
idempotent ids: firewall QUARANTINE/KILL (`AGENT-FW-<decision>`, high /
critical), pending approvals (`AGENT-APPROVAL-<approval>`, medium, with the
approve/deny endpoints), kill-switch / suspension events by people or the
behaviour monitor (`AGENT-SEC-<event>`), behaviour HIGH_RISK / CRITICAL
(`AGENT-BEHAVIOR-…`). The behaviour sweep, which the module left to the
host and nothing scheduled, now runs every minute (one instance at a time,
advisory lock).

---

## 2. Evidence: policy is enforced before sensitive tool execution

1. **Executor spy** (`test/policy-responses.test.ts`, assessment `PE-7`): an
   executor that, when it starts, looks up the decision that let it run in
   `firewall_decisions` — it is always there, and ALLOW/WARN. With the
   decision log made unwritable, the executor never runs (`firewall.log_unavailable`).
2. **Adversarial matrix** through the library executor path, each with a
   spy that must stay at 0 calls, a decision row that must already exist,
   and no tool ticket for that decision:

   | Attack | Decision | Rule |
   |---|---|---|
   | Privilege escalation: tool never granted | BLOCK | `permission.not_granted` |
   | Unauthorized tool: shell interpreter | BLOCK | `shell.denied_command` |
   | Unauthorized tool: not a tool at all | BLOCK | `tool.invalid_call` |
   | Exfiltration: mail outside the organisation | BLOCK | `email.recipient_not_allowed` |
   | Exfiltration: unlisted host | BLOCK | `egress.not_allowlisted` |
   | Exfiltration: cloud metadata | BLOCK | `egress.internal_address` |
   | Credential theft: protected table | BLOCK | `db.protected_table` |
   | Credential theft: secrets file | BLOCK | `file.sensitive_path` |
   | Cross-tenant data: SQL on another org | **QUARANTINE** | `sql.foreign_tenant` |
   | Dangerous chaining: pipeline hidden in args | BLOCK | `shell.shell_syntax` |
   | Policy bypass: state change without a person | **CONFIRM** | `confirm.permission` |
   | Credential theft: Legion token sent out | **KILL** | `http.legion_secret` |

3. **Approval bypass attempts**: changed argument, replay, other agent,
   forged id, malformed id, expired, denied, agent approving itself,
   viewer / non-owner analyst / other tenant approving — all refused; the
   exact call runs once. Monitor mode does not waive approval. A suspension
   after approval still stops the call.
4. **HTTP guard**: a guarded route's handler never runs on CONFIRM (counter stays 0).
5. **Server end-to-end** (`server/tests/agent-security.test.ts`): an agent
   resolving an alert waits for a person — the alert row is untouched until
   approval, changes once after, and a replay changes nothing; cross-tenant
   SQL quarantines before the answer (next request 401) and raises a high
   alert only in the agent's own tenant; Legion-token exfiltration kills
   (credential can no longer mint tokens) with a critical alert.
6. **Attack assessment** (pinned scenarios, run in CI with provenance): new
   category *Policy enforcement* PE-1…PE-7.

   Assessment totals (63 pinned scenarios, product defaults):

   | | DEFENDED | PARTIAL | NOT DEFENDED |
   |---|---|---|---|
   | Before this phase (56 scenarios) | 52 | 3 (EP-4, IMP-5, KSB-5) | 1 (CT-5) |
   | After (63 scenarios, incl. PE-1…PE-7) | **61** | 2 (EP-4, IMP-5) | **0** |

   KSB-5 is fixed (`includeServiceAccounts`); CT-5 was a scenario that
   expected a rule name the product deliberately does not reveal (a
   foreign agent id is answered exactly like a nonexistent one) — the
   scenario now checks refusal *and* indistinguishability. Six earlier
   scenarios' "legitimate baseline" steps expected an immediate ticket for
   a tool write; under the new default that needs a person, so those steps
   now go through a real approval. No scenario's attack step was relaxed.

---

## 3. Compatibility and migration

- **Schema**: new table `agent_action_approvals` (created idempotently).
  The `decision` CHECK constraints on `firewall_decisions` and
  `tool_call_audit` are widened to the six decisions: new installs get the
  superset directly; existing ones are upgraded by `WIDEN_DECISIONS_SQL`,
  which runs **in its own short transaction** before the main migration,
  with `lock_timeout 3s` and up to 5 retries on lock timeout / deadlock,
  adds the constraint `NOT VALID` (no table scan; existing rows already
  comply) and is a catalog read once done. Tested by simulating an old
  database.
- **Behaviour change you will notice**: agents that used `tool.*:write` or
  `tool.shell:execute` now receive `403 approval_required` until a person
  approves each action. This is the intended secure default ("AI does not
  silently perform sensitive actions"). An organisation that deliberately
  wants unattended tool writes sets `responses.confirm.permissions` to a
  narrower list in its firewall policy (audited, versioned).
- Agents that tried cross-tenant access, laundering, injection spreading
  or credential exfiltration are now taken offline, not just refused.
  Tenants can narrow `quarantineOn` / `killOn`.
- API error bodies keep `code`, `message`, `decisionId`, `rules`; they add
  `decision`, `approval`, `containment`. New codes: `approval_required`,
  `agent_quarantined`, `agent_killed`. The audit reason format is unchanged.

---

## 4. What is not covered / residual risk

- **Detection is heuristic where it must be**: tool-poisoning and prompt
  injection classifiers are pattern-based; a sufficiently novel poisoned
  description can pass as clean. The structural controls do not depend on
  them: the untrusted-content hold, per-action approval for world-changing
  tools, pinned tool hashes, and permission/egress policy still apply.
- **Approval quality depends on the person**: the approval shows the
  redacted action preview; an approver who approves blindly approves
  whatever was asked (bounded to that one exact call, once).
- **No dashboard UI for approvals yet**: people approve via the API; the
  SOC alert carries the endpoints. Building the queue in the frontend is
  the obvious next step.
- **Library hosts** that call `tools.execute()` directly must pass
  `ctx.approvalId` themselves to use an approval (HTTP agents use the header).
- Velocity limits are per instance (as before).
- Remaining assessment findings not addressed in this phase: **EP-4**
  (analysts may delegate tier-2 tool authority — mitigated because each use
  now needs admin/owner approval by default, but the delegation itself is
  still allowed) and **IMP-5** (`externalSystem()` is an audit label, not
  authentication — the server's Wazuh webhook verifies HMAC itself since phase 2).

---

## 5. Changed files

**New**
- `packages/agent-identity/src/firewall/approvals.ts` — approval store (digest-bound, single-use, expiring)
- `packages/agent-identity/src/firewall/tool-poisoning.ts` — tool-definition poisoning scanner
- `packages/agent-identity/src/registry.ts` — agent registry
- `packages/agent-identity/test/policy-responses.test.ts` — adversarial / evidence suite (33 tests)
- `packages/agent-identity/assessment/14-policy-enforcement.assess.ts` — PE-1…PE-7
- `server/src/agent-alerts.ts` — agent security → Legion alerts
- `server/tests/agent-security.test.ts` — end-to-end through the server (7 tests)

**Changed (package)** — `firewall/types.ts` (decisions, `permits()`), `firewall/engine.ts`
(compose, approvals, containment, poisoned-definition recording), `firewall/policy.ts`
(`responses`), `firewall/rules.ts` (MCP definition scan and hash check), `firewall/routes.ts`
(approvals, MCP inspect, agent approval status), `authorize.ts`, `tools/gateway.ts`,
`tools/routes.ts`, `tools/analyzers.ts`, `tools/findings.ts`, `skills/runtime.ts`,
`behavior/assess.ts`, `killswitch/service.ts` + `routes.ts` (`includeServiceAccounts`),
`routes/management.ts` (registry route), `schema.ts` (table + constraint migration),
`index.ts` (wiring, exports), `README.md`, `package.json` (security suite list).

**Changed (tests)** — suites that test controls *underneath* approvals (tool
analysis/tickets, kill switch, behaviour, A2A, DB executor) set
`responses.confirm.permissions: []` explicitly via `withoutApprovals()` in
their fixture policy (the product default is untouched and tested separately);
tests whose rule now quarantines assert the stronger outcome (QUARANTINE and
the agent's next call 401) instead of BLOCK. Assessment baseline steps
("legitimate call works") go through a real approval (`authorizeApproved`);
CA-1 turns quarantine off because it measures classification of sustained
probing; CT-5 now checks the deliberate "unknown recipient" answer; KSB-5
uses the new `includeServiceAccounts`.

**Changed (server)** — `agents.ts` (hooks, `startJobs`, `sweepBehavior`), `index.ts`,
`package.json` (security suite), `tests/cross-tenant-attacks.test.ts` (route coverage map).

## 6. Test evidence

All run locally on PostgreSQL 16 and Redis, 2026-09-30, on the final code:

| Suite | Result |
|---|---|
| `packages/agent-identity` — `npx vitest run` (26 files) | **802 passed** |
| of which `test/policy-responses.test.ts` (new) | 33 passed |
| `packages/agent-identity` — `npm run assess` (14 files) | 63 passed; 61 DEFENDED, 2 PARTIAL |
| `server` — `npx vitest run` with `LEGION_REQUIRE_FAILURE_INJECTION=1` (41 files) | 1000 passed, 1 failed → fixed (below) |
| of which `tests/agent-security.test.ts` (new) | 7 passed |
| `server/tests/webhook-auth.test.ts` after the fix, 3 consecutive runs | 80 / 80 each |
| `ops/tests/e2e-wazuh.mjs` (built API as app role, real integration script, agents) | all checks passed |
| typecheck (package, server), package build, server build, CI gate checks | OK |

The one server failure was a pre-existing flaky assertion (phase 2): the
webhook-rejection log line prints the first four characters of a base64url
key id, which may contain `-`, and the test's regex allowed only `\w`
(~12% of runs). The regex now matches base64url.

One earlier full server run showed 15 failures ("relation machine_identities
does not exist", a deadlock in migrate, a disaster-recovery count mismatch).
Cause: I ran the package assessment against the same test database at the
same time, and its reset drops the agent tables. Re-run alone: clean. It
did prompt a real hardening: the constraint upgrade now runs in its own
short transaction with a lock timeout and retries (section 3).
