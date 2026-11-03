# Multi-tenant isolation

How Legion keeps one organisation's data away from another, what enforces it,
and which tests prove it. Audit of 2026-09-29.

## The model

| Rule | Where it is enforced |
|---|---|
| The tenant comes from the authenticated principal, never the request | `authenticate` (server/src/index.ts): the user row is loaded from the JWT subject and the token's `tenant_id` must equal the row's. Machines: `principal.ts` derives the tenant from the credential row. No handler reads a tenant id from body, query or header (a supplied one is ignored; the agent message API compares a claimed tenant and refuses a foreign one). |
| Every tenant-owned query is scoped | Store functions take `tenantId` and put `tenant_id = $1` in SQL. Objects addressed by id (`/alerts/:id`, `/users/:id`, credentials) are looked up by `(tenant_id, id)`; a foreign id is a 404, indistinguishable from a missing one. Alert ids are unique per tenant only, so a shared id always resolves to the caller's copy. |
| Background work carries the tenant of the row | Outbox rows store `tenant_id` and the recipient at enqueue time (from the alert's own tenant); the worker publishes realtime frames to `row.tenant_id` and mails `row.recipient`. Agent-layer notices and kill-switch activations carry their tenant. |
| Realtime is per tenant and re-authorized | The socket's tenant is taken from the user record at the handshake (Origin-checked, cookie-authenticated). **New:** each socket remembers the user and token version it was authorized for; sockets are closed at once when that user is deactivated, demoted, or has sessions revoked on this instance, and every instance re-checks all its sockets against Postgres on the heartbeat interval (user active, same tenant, same token version, tenant not blocked). |
| AI sees one tenant | Copilot context is `recentAlerts(tenantId)`; explain loads `getAlert(tenantId, id)` first (a foreign id is a 404 before any provider call). Pseudonymisation maps are per request; AI quotas and settings are per tenant. |
| Audit logs are per tenant | Server audit rows are written with the actor's tenant and listed by tenant. Agent-layer hash chains are keyed by tenant (`chain_key`), including their `verify` endpoints. |
| Exports/lists | There is no file export endpoint; every list endpoint (alerts, feed, sync, stats, assets, users, audit, deliveries, credentials, billing, agent-layer logs) is tenant-scoped. The reports page is built from these. |

## Found and fixed in this audit

1. **Live sockets outlived revocation (fixed).** A socket was authorized only at the handshake, so a user who was deactivated or demoted, whose sessions were revoked (password reset, refresh-token reuse), or whose organisation lost access kept receiving that organisation's alerts until they closed the tab. Now: an immediate local close on every revocation, plus a periodic re-authorization on every instance. If the re-check itself fails (a database blip), nothing is closed; the next round decides.
2. **Agent SQL analyzer: the tenant scope could be bypassed (fixed).** `/agent/v1/tools/authorize` checked tenant scope with regular expressions. Each of these contains the text `tenant_id = $1` and still reads or writes other organisations' rows:
   - `NOT (tenant_id = $1)`
   - `(tenant_id = $1) IS NOT TRUE`
   - `CASE WHEN tenant_id = $1 THEN false ELSE true END`
   - comma joins
   - a self-join scoped twice on one alias
   - unscoped subqueries or UNION branches
   - `UPDATE … SET tenant_id = <other>`
   - `INSERT … ON CONFLICT DO UPDATE` onto another tenant's row
   - `INSERT … SELECT`

   A quoted `"set_config"(…)` also got past the function denylist and could re-point the row-level-security tenant setting. The check now runs on PostgreSQL's own parse tree (`libpg-query`, `packages/agent-identity/src/tools/sql-ast.ts`): every table read at every level must be restricted by a top-level `AND` conjunct `<table>.tenant_id = $n` bound to the caller's tenant, and function names come from the AST. This was latent — the Legion server wires no agent database pool, and the default policy opens no tables — but it would have become exploitable once an administrator opened a table to agents.
3. **Cross-tenant agent-id oracle (fixed).** Messaging an agent id that exists in another organisation returned `a2a.cross_tenant`, where an id that exists nowhere returned `a2a.recipient_unknown`. The sender's own logs and trust graph recorded the same distinction. Either one let an organisation probe which agent ids exist elsewhere. Both cases are now identical everywhere the sender's organisation can look, and the operator log records the cross-tenant attempt. A tenant id the sender names explicitly is still refused as cross-tenant; that reveals nothing, because the sender supplied it.

## Reviewed and left as is

- `updateUser(id)` has no tenant condition; every caller first resolved the user with `findUserInTenant`, or is the user themselves. The static guard records this.
- Inviting an address already registered in another organisation answers "already in use" and nothing else. Email is the global login identifier, and public sign-up gives the same answer, so this is no new disclosure.
- The AI circuit breaker is shared: one organisation's provider failures can switch AI to the fallback for everyone for a while. That affects availability, not data.
- The core tables have no Postgres row-level security; isolation is enforced in the application, guarded by the tests below. The agent layer has its own RLS option. Adding RLS to the core would be defence in depth, and needs a per-request `SET LOCAL` design.

## Tests

- `server/tests/cross-tenant-attacks.test.ts`: tenant A (admin, analyst, viewer and an AI agent) attacks tenant B's alerts, users, assets, audit log, AI context, WebSocket events, notifications, credentials, billing and every list endpoint. Each attack checks both that nothing of B's comes back and that nothing of B's changes. It also checks forged tokens, client-supplied tenant ids, shared alert ids, socket revocation, and that every parameterised route appears in the IDOR matrix.
- `server/tests/tenant-query-guard.test.ts`: static check. Every SQL statement touching a tenant-owned table must contain `tenant_id` or appear on a reviewed exception list that states why it is safe. Alerts, assets and the audit log have no exceptions. Dynamic WHERE builders must start from `tenant_id = $1`.
- `server/tests/tenant-isolation-sweep.test.ts` (existing): an every-endpoint sweep, the live feed, and the AI.
- `packages/agent-identity/test/tools-analyzers.test.ts`: every bypass above, plus scoped queries that must still pass. Also `a2a.test.ts` and `firewall.test.ts` for the oracle.
- Mutation check: nine realistic isolation bugs, injected one at a time, were each caught by the suite:
  - an unscoped alert lookup
  - an unscoped user lookup
  - an unscoped audit list
  - Copilot reading all tenants
  - realtime broadcasting to every tenant
  - revalidation disabled
  - deactivation leaving sockets open
  - an alert email sent to the wrong tenant
  - a credential revoke without a tenant check

  A newly planted unscoped query fails the static guard.
