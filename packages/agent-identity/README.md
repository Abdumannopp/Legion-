# @legion/agent-identity

Gives every AI agent (and every non-AI machine) in Legion its own identity,
owner, permissions and audit trail, so every action it takes is traceable to
it, and so an AI agent is never served as an anonymous API client. Every
agent action then passes a central, deterministic **agent firewall** before it
runs ([below](#agent-firewall)).

> **Status.** Complete and tested as a standalone module (173 tests, most against
> real PostgreSQL 16). **Not yet wired into Legion's server**: `server/` was not in
> the repository when this was written. Wiring is the ~15 lines in
> [Integration](#integration); nothing in the existing human login needs to
> change.

## The four principal types

Every request is resolved to exactly one of these and stored on `req.principal`:

| Type | Who | How it authenticates |
|---|---|---|
| `human` | A person | Legion's existing cookie login (called through `HostAdapter`, never reimplemented) |
| `ai_agent` | An AI system acting on its own | Access token `lgt_…` obtained with an agent credential `lga_…` |
| `service_account` | A non-AI machine (script, integration) | Access token `lgt_…` obtained with a service credential `lgs_…` |
| `external_system` | Everything else: sensor webhooks, anonymous traffic | Nothing, or its own scheme; labelled by name with `guards.externalSystem("wazuh-webhook")` |

Rules enforced on every request:

- **A self-declared AI agent without a Legion identity is refused (401) and
  audited.** This covers `GPTBot`, `ClaudeBot`, `Claude-User`, `PerplexityBot`
  and similar user agents, plus the `x-legion-agent` and `Signature-Agent`
  headers. Ordinary browsers are unaffected. This catches *honest* agents;
  agents that spoof a browser need behavioural detection (a later phase).
- **Human session + machine token in the same request → 400.** An agent
  cannot borrow a person's session, and a person's authority is never
  silently mixed with an agent's.
- **Long-lived credentials only work at `/agent/v1/token`.** Everything else
  needs a short-lived access token.
- **Machines can never manage identities**, not even their own.

## Identity record

| Field | Meaning |
|---|---|
| `id` | UUID |
| `kind` | `ai_agent` or `service_account` |
| `name`, `description` | Unique per tenant among live identities |
| `tenantId` | The only tenant it can ever act in |
| `ownerUserId` | The accountable person. Must be active in the same tenant |
| `status` | `active` · `suspended` · `revoked` (final) |
| `permissions` | Granted permissions (see below) |
| `riskLevel` | `low` · `medium` · `high` · `critical` |
| `createdAt`, `createdBy`, `updatedAt` | |
| `lastActivityAt` | Last authenticated use (written at most once a minute) |
| `expiresAt` | Optional hard end date |

### Permissions and risk

| Permission | Tier | Implied risk |
|---|---|---|
| `alerts:read`, `assets:read`, `stats:read` | 0 read | low |
| `alerts:comment` | 1 annotate | medium |
| `alerts:update_status`, `assets:update` | 2 change state | high |

- **Tier 3 does not exist for machines.** Users, roles, credentials,
  settings, exports and containment cannot be granted to an agent at all.
- **An identity never exceeds its owner.** Permissions must fit within the
  owner's role when granted, and at every request the effective permissions
  are re-limited to the owner's *current* role. Demote the owner and the
  agent shrinks; deactivate the owner and the agent stops (`owner_inactive`).
- **Risk has a floor set by the permissions.** Administrators may raise it,
  never lower it. `critical` puts the agent on hold: it can't get or use
  tokens until an administrator lowers the level.
- **Token lifetime follows risk:** 15 minutes for low/medium, 5 minutes for
  high.

## Audit trail

Table `principal_audit_log`, one row per event, for all four principal types:
principal type, id and name, the owner it acted for, the credential used,
action, resource, outcome (`attempt`/`success`/`failure`/`denied`), reason,
request id (also returned as the `x-request-id` header), IP, user agent.

- **No trace, no action.** `requirePermission` commits an `attempt` row
  *before* the handler runs. If that write fails, the request gets 503 and the
  action does not happen. The `success`/`failure` row is written after the
  response.
- **Identity changes and their audit rows commit in one transaction.**
- **Append-only.** Triggers refuse `UPDATE`, `DELETE` and `TRUNCATE`.
- **Tamper-evident.** Each row's hash covers its content and the previous
  row's hash, one chain per tenant. `GET /audit/principal-events/verify`
  recomputes the chain and names the first altered row. This detects even a
  superuser who disables the triggers, unless they rewrite every later hash
  too. Exporting the latest hash off the server (for example, in the daily
  backup) closes that gap.
- **Flood-resistant.** Failures from unknown callers are sampled at 20 per
  IP per minute. Failures that target a real identity (wrong secret for a
  real credential, expired or revoked token) are always recorded against
  that identity.

## API

People (Legion session required):

| Method & path | Who | Purpose |
|---|---|---|
| `POST /agents` | admin | Create. Returns the credential secret **once** |
| `GET /agents` | admin, analyst | List the tenant's agents |
| `GET /agents/:id` | admin, analyst | Details + credential metadata (never secrets) |
| `PATCH /agents/:id` | admin | Name, description, owner, permissions, risk, expiry (the change is audited as a diff) |
| `POST /agents/:id/suspend` | admin **or the owner** | Stop now; kills all its tokens |
| `POST /agents/:id/resume` | admin | Back to active (a new token is required) |
| `POST /agents/:id/revoke` | admin | Final; kills credentials and tokens |
| `POST /agents/:id/credentials` | admin | Add a credential (max 2 usable, for rotation) |
| `DELETE /agents/:id/credentials/:cid` | admin | Revoke one credential and its tokens |
| `GET /agents/:id/activity` | admin, analyst | What it did and what was done to it |
| `/service-accounts/…` | same | Same API for service accounts |
| `GET /audit/principal-events` | admin | Tenant audit trail, filter by `principalType`, `principalId` |
| `GET /audit/principal-events/verify` | admin | Verify the hash chain |

Machines:

| Method & path | Auth | Purpose |
|---|---|---|
| `POST /agent/v1/token` | `Bearer lga_…` / `lgs_…` | Exchange credential for an access token |
| `GET /agent/v1/me` | `Bearer lgt_…` | Who am I: granted vs effective permissions, risk, owner |
| `POST /agent/v1/token/revoke` | `Bearer lgt_…` | End this token early |

```bash
curl -s -X POST https://legion.example/agent/v1/token -H "Authorization: Bearer lga_…"
# {"access_token":"lgt_…","token_type":"Bearer","expires_in":900,…}
curl -s https://legion.example/agent/v1/me -H "Authorization: Bearer lgt_…"
```

## Agent firewall

Every action by an AI agent or service account is decided **ALLOW**, **WARN**
or **BLOCK** by one engine (`AgentFirewall.evaluate`) before it runs, and the
decision is written to `firewall_decisions` first. If the decision can't be
written, or the policy can't be read, the answer is BLOCK.

### What is evaluated

| Input | Where it comes from |
|---|---|
| Agent identity | The authenticated token (status, risk, credential) |
| Tenant | Agent's tenant vs. the target's tenant |
| User delegation | `x-legion-on-behalf-of: <userId>`, checked against a grant **that person** created (`POST /firewall/delegations`), their current role, and the agent's grants |
| Requested action & permission | The route or executor. For tools, the policy's permission for the tool wins over the caller's claim |
| Target resource | Type, id and owning tenant |
| Sensitivity | `public` < `internal` < `confidential` < `restricted`. The policy can raise a resource type's level, never lower it. Data leaving Legion is at least `confidential`; `restricted` is never reachable |
| Risk | Deterministic score: agent risk + permission tier + sensitivity + external effect + delegation + agent hops + unusual rate |
| Destination | API resource, file path, `db:table`, URL, `tool:x`, `mcp:server/tool`, `agent:id` |

### Surfaces and their rules

| Surface | Enforced by | Key rules (hard = cannot be relaxed) |
|---|---|---|
| APIs | `guards.requirePermission` / `guards.traced` | permission, tenant, delegation, sensitivity, risk |
| Files | `firewall.readFile` / `writeFile` | allowed roots only (none by default); `..` and symlink escapes caught at the real path; never `.env`, keys, `.ssh`, `/proc`…; writes never follow a symlink (`O_NOFOLLOW`) |
| Databases | `firewall.execute({surface:"database"})` | no raw SQL or DDL; identity, secret and audit tables are never reachable (not even via policy); table and operation allowlist; the tenant filter must be the agent's own; row limit |
| External services & network | `firewall.request` | https only; no credentials in URLs; loopback, private, link-local and cloud-metadata addresses refused, including decimal, hex, IPv4-mapped and NAT64 forms; host and port allowlist; **every DNS answer re-checked at connect time** (DNS rebinding); each redirect evaluated again; secrets in outgoing data refused |
| Tools | `firewall.execute({surface:"tool"})` | unregistered tool → BLOCK; declared arguments only; size cap; secrets refused; URLs passed to externally-acting tools checked like egress |
| MCP tools | `firewall.callMcpTool` | approved server and tool only; the tool definition's SHA-256 is pinned, so a changed description or schema (tool poisoning, "rug pull") → BLOCK |
| Agent-to-agent | `POST /agent/v1/messages`, `x-legion-message-id` | pair allowlist (none by default); no laundering (you can't ask another agent for what you may not do); recipient must hold the permission; no cycles; depth ≤ `maxDepth`; the recipient's follow-up is limited to what the message asked; the chain is stored server-side and never read from headers |

**Backstops:**
- Machine tokens only work under the agent API (`/agent/v1`), so an agent can
  never reach a human route that has no firewall in front of it.
- An agent request that completes without a firewall decision (a route added
  without a guard) is recorded as `firewall.unguarded_route` in the audit
  trail.

### Decisions

- **Hard** rule hit → BLOCK, always.
- **Soft** rule hit (host or port not allowlisted, row limit, rate limit,
  agent pair not allowlisted, risk score ≥ `blockAt`) → BLOCK in `enforce`
  mode. In `monitor` mode it becomes WARN, logged with `would_block = true`.
- WARN hit or score ≥ `warnAt` → WARN: the action runs, flagged in the
  `x-legion-firewall` response header, the log, and the `onFirewallDecision`
  hook (connect this to Legion's alerting).
- **An AI/LLM is never the decider.** `firewallAdvisors` run only after a
  non-BLOCK deterministic decision. They can only return WARN or BLOCK, each
  is limited to 2 seconds, and failures are logged and ignored. Tests prove
  an advisor can't turn a BLOCK into an ALLOW.

### Decision log (`firewall_decisions`)

Each row records:
- **who:** agent, owner, credential, token
- **for whom:** delegated person and grant
- **through which agents:** the chain and message
- **what:** surface, action, permission, resource
- **how sensitive, and where:** sensitivity and destination
- **the outcome:** decision, mode, `would_block`
- **why:** risk score and factors, every rule hit with its reason, any
  advisor verdicts, the policy version
- **the input:** a SHA-256 of the full input plus a redacted preview (strings
  cut at 64 characters, secrets replaced)
- the request id and IP

The log is append-only and hash-chained per tenant. Endpoints:
`GET /firewall/decisions` (filter by `decision`, `principalId`, `surface`)
and `GET /firewall/decisions/verify`.

### Policy (`GET`/`PUT /firewall/policy`)

- Per tenant, validated on save, versioned (every version kept), and every
  change audited.
- **Deny by default:** no files, tables, tools, MCP servers, external hosts
  or agent pairs until an administrator opens them.
- **The schema itself refuses unsafe entries:** `*`, internal names,
  private or metadata IPs, protected tables, and `/` as a file root.
- Policies are cached for 5 seconds per instance.

## Integration

Legion's server already has everything this needs (Express 5, `pg`,
`cookie-parser`). In `server/`:

1. Add the dependency: `"@legion/agent-identity": "file:../packages/agent-identity"`.
2. Write the adapter over the **existing** auth code; don't change that code:

   ```ts
   const host: HostAdapter = {
     // Wrap whatever the current `auth` middleware does to read the cookie.
     authenticateHuman: async (req) => {
       const s = await verifySessionFromCookie(req);           // existing function
       return s && { userId: s.user.id, tenantId: s.user.tenant_id, role: s.user.role };
     },
     getUser: async (tenantId, userId) => {
       const u = await store.getUserById(userId);             // existing repository
       return u && u.tenant_id === tenantId
         ? { id: u.id, tenantId: u.tenant_id, role: u.role, status: u.status } : null;
     },
   };
   ```
3. Wire it into `index.ts`, after `cookieParser()` and `express.json()` and
   before the existing routes:

   ```ts
   const identity = createAgentIdentity({ pool, host, exemptPaths: ["/health", "/security-events/webhook", "/billing/webhook"] });
   await identity.migrate();                                  // next to the existing migrate()
   app.use(identity.principal);
   app.use("/agent/v1", identity.agentApi);
   app.use("/agents", identity.agents);
   app.use("/service-accounts", identity.serviceAccounts);
   app.use("/audit/principal-events", identity.auditApi);
   app.use("/firewall", identity.firewallApi);
   setInterval(() => identity.purgeExpiredTokens().catch(() => {}), 3_600_000).unref();
   ```
4. Expose agent actions as **new** routes under `/agent/v1/…` that call the
   same service functions as the human routes, each behind
   `identity.guards.requirePermission("<permission>", { resource, sensitivity })`.
   Any file, database, outbound HTTP, tool or MCP call that code makes for an
   agent goes through `identity.firewall.readFile / writeFile / execute /
   request / callMcpTool`. Leave the existing human routes as they are.
5. Add the foreign keys noted in `src/schema.ts` once the `tenants.id` and
   `users.id` column types are confirmed.
6. Mount `identity.principal` at the app root: the credential exemption
   compares `req.path` with `${agentBasePath}/token`.

**What changes for existing users after wiring:** nothing, except (a)
requests from self-declared AI user agents without an identity get 401, and
(b) a request carrying both a session cookie and a `Bearer lg…` token gets
400. Browsers do neither. `/health` and the webhooks listed in
`exemptPaths` are untouched.

## Security notes

- Credentials and tokens are 256-bit random values stored as SHA-256 hashes
  (a slow hash like bcrypt adds nothing for full-entropy secrets and would
  cost latency on every request). Prefixes `lga_`, `lgs_` and `lgt_` let
  secret scanners recognise leaked keys.
- The identity, its credential and its owner are checked on **every** request,
  so suspension, revocation and owner changes take effect immediately, not
  when a token expires.
- The column types in the schema are `text` for `tenant_id` and
  `owner_user_id` until the host schema is available. Tenant scoping is
  enforced in every query and covered by tests.

## Known limitations

- An agent operating a *stolen human session* still looks human. Telling
  those apart needs session-behaviour detection (design phase 4).
- Tokens are bearer tokens. Proof-of-possession (DPoP/mTLS) is design
  phase 3+.
- The `success`/`failure` audit row is written after the response. A crash in
  between leaves the `attempt` row without an outcome: the action is still
  attributed, but its result is unknown.
- Each guarded agent request writes one decision row and two audit rows under
  per-tenant locks. That's fine at SOC-console volumes; very high-rate agents
  would need batching.
- **Firewall coverage depends on the host using the executors.** Code that
  opens files, sockets or SQL for an agent directly bypasses the firewall.
  The confinement and unguarded-route detection catch HTTP routes, not
  in-process calls.
- **The rate limit is per instance** (in memory). With several instances an
  agent gets that rate on each; use Redis to share it.
- **Policy changes reach other instances within 5 seconds** (cache).
- **Monitor mode lets soft-blocked actions run**, including calls to
  non-allowlisted public hosts. Use it only for rollout.
- **Small race window in file access:** a directory swapped for a symlink
  between the path check and the open is not caught. Only the final
  component is protected (`O_NOFOLLOW`).
- **A relayed message can be cited repeatedly until it expires** (1 hour).
  Every use is logged.
- **Secret scanning uses high-confidence formats only.** Unusual secrets pass.
- **Payloads from other agents are untrusted text.** The firewall stops
  credentials, not prompt injection inside a message.
- **Outbound HTTPS on the allowed path hasn't been exercised against a live
  server** (no internet in the test environment). The blocking paths are
  tested.

## Development

```bash
docker run -d --name legion-test-pg -e POSTGRES_USER=legion -e POSTGRES_PASSWORD=legion-test \
  -e POSTGRES_DB=legion_test -p 127.0.0.1:55432:5432 postgres:16-alpine
npm ci
npm run check && npm test && npm run build
```

Tests use `TEST_DATABASE_URL` (default above) and drop the module's own
tables before each test. Point them at a dedicated database.
