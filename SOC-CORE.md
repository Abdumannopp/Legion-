# SOC core (v0)

The SOC core is the part of Legion that decides, asks, prepares and records
**actions** — blocking an address, changing an alert, disabling an account —
whoever proposes them: a person, one of the five agents, or Legion itself.

**v0 does not perform any action.** It runs in two modes only:

| Mode | What happens |
|---|---|
| `shadow` | The action is evaluated and the decision is recorded. Nothing else. |
| `simulation` | The full path runs — policy, approval, queue — and the last step **computes** what would happen, using reads only. |

`live` is refused by the policy engine, by the action engine, and by the
database itself (a `CHECK` on `action_requests.execution_mode`). There is no
code that executes an action, and tests fail if any is added.

## The path of an action

```
propose ──► catalog + input check ──► policy ──┬─ DENY ─────────────► denied
 (person,     (closed list, strict     (pure,  ├─ RECORD_ONLY ──────► recorded
  agent,       schemas)                 deter- ├─ REQUIRE_APPROVAL ─► approval request ─► person(s) decide ─┐
  Legion)                               minist)└─ ALLOW ───────────────────────────────────────────────────┤
                                                                                                         ▼
                                                     queued ──► (runtime job) ──► running ──► simulated (result, side_effects: "none")
```

Every step is a row in `action_events` and an event in the audit chain.

## Modules

| Module | Code | Tables (migration) |
|---|---|---|
| Versioned migrations | `db/pool.ts` (`migrationFiles`, `applyVersionedMigrations`) | `legion_migrations` |
| Policy Engine | `src/policy/` | `policy_documents`, `policy_active`, `policy_decisions` (0001) |
| Approval Engine | `src/approvals/engine.ts` | `approval_requests`, `approval_decisions` (0002) |
| Action Engine | `src/actions/` | `action_requests`, `action_events`, `soc_controls` (0003) |
| Agent Orchestrator | `src/orchestrator/engine.ts` | `workflow_runs` (0004) |
| Background Runtime | `src/runtime/` | `soc_jobs` (0005) |
| Integration layer (foundation) | `src/integrations/envelope.ts`, `src/integrations/action-connectors.ts` | — |
| Memory and Learning (foundation) | `src/memory/` | `soc_memory`, `learning_signals` (0006) |
| Audit and observability | `src/audit/` | `soc_audit_events` (0007) |

HTTP routes are in `src/soc-routes.ts`.

## Rules that no policy can change

- **Unknown action, unknown agent, an agent outside its catalog role → refused.**
- **DENY wins.** Precedence: DENY > RECORD_ONLY > REQUIRE_APPROVAL > ALLOW.
- **Critical (R4) actions always need approval** — two different people, each
  with a current two-factor code; the person who asked cannot approve
  (enforced in code and by a database `CHECK`).
- **High-risk (R3) actions proposed by an agent or by Legion need approval.**
- **Anything a model proposed needs approval above read-only.**
- **Who acts is set by the server** (session or engine), never by a request
  body, an alert or a model.
- **Approvals are bound to the exact action** (a digest of workspace, action,
  input and mode), expire, and are consumed once, atomically.
- **Every table is per workspace**; the tenant-query guard test now scans all
  of `src/` recursively.
- **Memory can only make Legion more careful** and is written by people, never
  by a model. **Learning only suggests**; it changes nothing.

## Risk classes (catalog: `src/policy/catalog.ts`)

| Class | Meaning | Actions |
|---|---|---|
| R0 | read only | `alert.explain`, `alert.triage` |
| R1 | small, reversible | `alert.set_status`, `notify.admins` |
| R2 | reversible change to protection | `ip.unblock` |
| R3 | impacting | `ip.block`, `payment.reject` |
| R4 | critical | `payment.release`, `account.disable`, `host.isolate` |

## Policy documents

Admins (`policy:manage`) write a small JSON document; every save is a new,
immutable version (optimistic concurrency with `expected_version`):

```json
{
  "schema": 1,
  "default_autonomy": "ASSIST",
  "agents":  { "Oracle": { "autonomy": "AUTONOMOUS" } },
  "actions": { "notify.admins": { "autonomy": "OBSERVE" } },
  "rules": [
    { "id": "no-payments", "effect": "DENY", "actions": ["payment.release"], "reason": "finance only" }
  ]
}
```

Autonomy: `OBSERVE` (record only), `ASSIST` (ask a person), `AUTONOMOUS`
(act on R1–R2; R3+ still asks). No policy (D0) = `OBSERVE`.
`POST /policy/simulate` evaluates a draft without recording anything.

## Shadow comparison with today's behaviour

With `POLICY_ENGINE_MODE=shadow` (default) the existing paths — manual block
and unblock, automatic blocking, alert status, payment release/reject — are
also evaluated and recorded in `policy_decisions` with `legacy_outcome`. They
behave exactly as before. `GET /soc/metrics` → `shadow.divergent` counts how
often the code acted where the policy would not have. That number, over real
traffic, is the evidence needed before any enforcement is considered.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `POLICY_ENGINE_MODE` | `shadow` | `off` records nothing. No enforcing value exists. |
| `RUNTIME_WORKER` | `on` | `off` for an API-only replica. |
| `RUNTIME_POLL_SECONDS` | `5` | How often the worker looks for due jobs. |
| `ORCHESTRATOR_AUTO_MODE` | `off` | `shadow`: run the alert workflow for each new alert, record only. |
| `SOC_AUDIT_KEY` | (derived from `JWT_SECRET`) | Key of the audit chain. Set it, and keep it: changing it (or `JWT_SECRET` while unset) makes older events fail verification. |

## Routes

| Route | Permission |
|---|---|
| `GET /policy`, `/policy/versions`, `/policy/decisions`, `POST /policy/simulate` | `policy:read` (analyst) |
| `PUT /policy`, `POST /policy/rollback` | `policy:manage` (admin) |
| `GET /approvals`, `/approvals/:id` | `approvals:read` (analyst) |
| `POST /approvals/:id/decision` | `approvals:decide` (admin) + step-up limiter |
| `POST /actions`, `POST /actions/:id/cancel` | `actions:propose` (analyst) |
| `GET /actions`, `/actions/:id`, `/actions/controls` | `actions:read` (analyst) |
| `POST /actions/controls` (emergency stop) | `actions:control` (admin) |
| `GET /workflows`, `/workflows/runs`, `/workflows/runs/:id` | `workflows:read` (analyst) |
| `POST /workflows/:name/runs` | `workflows:run` (analyst) |
| `GET /runtime/status`, `/soc/metrics` | `runtime:read` (admin) |
| `GET /integrations/capabilities` | `integrations:read` (viewer) |
| `GET /memory`, `/learning` | `memory:read` (analyst) |
| `POST /memory`, `DELETE /memory/:id` | `memory:write` (analyst) |
| `GET /soc/audit`, `/soc/audit/verify` | `audit:read` (admin) |

## Known limits of v0

- Nothing is executed. Live execution needs: a migration allowing `live`, a
  live executor per connector behind approval consumption, connector
  credentials, and an explicit decision based on shadow data.
- The dashboard has no screens for these routes yet (API only).
- Workflows are code-defined; there is one (`alert_response`). No model is
  used by the orchestrator.
- The audit chain is verified on demand (`/soc/audit/verify`); there is no
  external checkpoint of chain heads yet, so an attacker with both database
  write access and the key could rebuild a chain.
- Appends to the audit chain are serialised per workspace (advisory lock);
  very high action volumes in one workspace would queue on it.
- `policy_decisions`, `action_events`, `approval_decisions` and
  `soc_audit_events` are append-only and are not yet pruned by the retention
  job (memory is). They are erased with the workspace.
- Learning suggestions need at least 20 decisions per action.
