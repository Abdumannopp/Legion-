# @legion/agent-identity

Gives every AI agent (and every non-AI machine) in Legion its own identity,
owner, permissions and audit trail, so every action it takes is traceable to
it, and so an AI agent is never served as an anonymous API client. Every
agent action then passes a central, deterministic **agent firewall** before it
runs ([below](#agent-firewall)), and all external content that reaches a model
passes the [prompt-injection guard](#prompt-injection-protection). Every AI
tool call goes through the [tool gateway](#tool-security), and each agent's
behaviour is compared with its own normal role at runtime
([behaviour monitoring](#runtime-behaviour-monitoring)). Administrators can
stop a compromised agent at once with the
[emergency kill switch](#emergency-kill-switch). Agents asking other agents
for work pass [agent-to-agent controls](#agent-to-agent-security), recorded
in an auditable [Agent Trust Graph](#agent-trust-graph).

> **Status.** Complete and tested as a standalone module (534 tests, many against
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

## Prompt-injection protection

**Principle:** external content is data, never instructions. Detection helps,
but the protection doesn't depend on it:
- **Separation:** undetected injected text still arrives as wrapped data.
- **Action gating:** undetected injected text still can't trigger a sensitive
  action on its own.

### Four separate parts (`PromptAssembly`)

| Part | Where it comes from | How it is placed |
|---|---|---|
| 1. System instructions | `SYSTEM_PROMPTS` in code only | Chosen by key. The compiler rejects runtime text (`test/compile-guards.ts`), so external content can never become a system instruction |
| 2. User intent | The signed-in person or authenticated agent | `USER REQUEST` section. Also classified, since injection-like intent usually means external text was pasted in as a request |
| 3. Trusted application data | Values Legion produced (ids, counts, times) | `TRUSTED APPLICATION DATA`, JSON-encoded, so a value can't start a new section |
| 4. Untrusted external content | Emails, web pages, security alerts, PDFs, documents, tickets, GitHub issues, API responses, user-generated content, other agents' messages, model output | Classified, sanitised, and wrapped between markers carrying a random per-prompt boundary. Content can't know that boundary in advance, so it can't close its own block; if it contains the boundary anyway, the forgery is removed and flagged |

**The system message always states the separation rules. There is no method
that moves content from part 4 into parts 1–3.**

### Detection: layered, not keyword filtering (`classifyContent`)

1. **Normalisation before analysis** undoes these tricks:
   - zero-width characters
   - invisible Unicode tag characters (ASCII smuggling); the hidden text is
     decoded and analysed
   - bidi overrides
   - Cyrillic and Greek lookalike letters
   - fullwidth and mathematical letters (NFKC)
   - letter-spacing and leetspeak

   The tests show a naive keyword filter missing each of these cases while
   the guard catches them.
2. **Structural signals that need no words at all:**
   - smuggled or invisible characters
   - words mixing alphabets
   - chat-template tokens and role labels
   - attempts to close the wrapper
   - a field whose content doesn't match its declared shape (a hostname
     containing sentences)
   - text hidden from people in HTML
   - base64, hex or percent-encoded blobs that *decode* to directives
   - image and link URLs that carry data out
3. **Statistical:** how much of the text instructs its reader. A description
   describes; an injection instructs. This signal contributes to the score
   but never decides alone, so ordinary runbooks stay clean.
4. **Directive patterns:**
   - overriding instructions, new personas, fake authority
   - addressing "the AI reading this"
   - hiding actions from people
   - asking for the prompt
   - SOC-specific attacks: closing or downgrading alerts, disabling
     monitoring, granting privileges, exfiltrating data

**Scoring:** the strongest finding per category is summed, capped at 100.
Several independent weak signals add up; repeating one phrase doesn't.
≥ 25 is **suspicious**, ≥ 60 **malicious**. The result is deterministic.

### When suspicious content is detected

| Requirement | What happens |
|---|---|
| **Record the event** | `content_ingestion_log`, against the principal the content reached. Append-only and hash-chained. Stores a digest, length, a 300-character redacted preview and the findings, never the raw content. If a flagged event can't be recorded, the caller gets an error instead of passing the content on |
| **Increase risk** | Suspicious: +10 to +25 on the agent's firewall risk score for `suspiciousWindowSeconds` (default 1 h). Malicious: +40 until reviewed |
| **Prevent unsafe actions** | Unreviewed malicious content puts the agent in **quarantine**. The hard firewall rule `content.quarantine` blocks everything that changes state (tier-2 permissions, file writes, database writes), acts outside Legion (egress, external tools), touches confidential data, or messages another agent. Reads continue, flagged WARN. The quarantine doesn't expire, so an attacker can't just wait it out |
| **Require stronger authorization** | Only an **administrator** can lift a quarantine (`POST /prompt-guard/acknowledge`), and must state what they reviewed (at least 10 characters, written to the audit trail). A later malicious event re-imposes the quarantine |

**Between agents:**
- A message whose payload is malicious is blocked (`a2a.injection_payload`),
  and the *sender* is quarantined, since an agent emitting injections is
  probably compromised.
- A suspicious payload is delivered, marked `trust: "untrusted"` with its
  classification, and recorded once against the recipient.

**Legion's own AI:** `reviewProposedAction(assembly, proposal)` means a
model's suggestion made after reading external content never auto-executes if
it is sensitive:
- `block` after malicious content
- `confirm` (a person must approve) after any external content
- `allow` only for read-only proposals or when no external content was
  involved

### API

| Endpoint | Who | Purpose |
|---|---|---|
| `POST /agent/v1/content/inspect` | agents | Submit external content the agent read. Returns verdict, findings, sanitised text and a ready-to-use wrapped envelope; flagged content counts against that agent |
| `GET /prompt-guard/events` | admin, analyst | Flagged events (filter: `verdict`, `principalId`, `source`) |
| `GET /prompt-guard/status/:principalId` | admin, analyst | Quarantined? Unreviewed counts |
| `POST /prompt-guard/acknowledge` | admin | Lift a quarantine, with a reason |
| `GET /prompt-guard/events/verify` | admin | Verify the hash chain |

### Retrofitting Oracle and Copilot (`server/src/ai.ts`)

Today these features fence alert data and rely on the system prompt's
wording (CHANGELOG-AUDIT §3). Replace the prompt building with:

```ts
const a = identity.contentGuard.createAssembly({ tenantId, principal: req.principal }, "oracle.explain_alert");
a.setUserIntent("Explain this alert");
a.addTrustedData("alert", { id: alert.id, severity: alert.severity, created_at: alert.created_at, mitre: alert.mitre });
a.addUntrustedContent("security_alert", alert.title, { sourceId: alert.id, fieldHint: "short_text" });
a.addUntrustedContent("security_alert", alert.summary, { sourceId: alert.id });
a.addUntrustedContent("security_alert", alert.full_log, { sourceId: alert.id });
a.addUntrustedContent("security_alert", alert.target, { sourceId: alert.id, fieldHint: "identifier" });
a.addUntrustedContent("security_alert", alert.source_ip, { sourceId: alert.id, fieldHint: "identifier" });
await a.settle();                               // refuses if a flagged item could not be recorded
const messages = a.toMessages();                // send these to OpenRouter / Groq
// show a.verdict in the UI; never auto-apply anything the model proposes:
// reviewProposedAction(a, proposal).decision === "allow" before acting.
```

**Everything that came from Wazuh is part 4:** title, summary, `full_log`,
hostnames, IPs, user names. Only values Legion computed are part 3. Treat
the model's answer as `model_output` if it is fed back into a later prompt.
When an agent is served alert content through `/agent/v1/…`, call
`identity.contentGuard.ingest({ tenantId, principal: agent }, "security_alert", text)`
so the risk follows the content to the agent that received it.

## Tool security

Every AI tool call passes through `ToolGateway.authorize` **before it runs**:
1. The call is validated against a strict shape for its tool family.
2. It is analysed deterministically.
3. The agent firewall decides ALLOW, WARN or BLOCK.
4. Blocked and high-risk calls are written to `tool_call_audit` first.

### What is verified on every call

| Check | How |
|---|---|
| Agent | The authenticated identity: status, risk, credential and owner, checked per request |
| Tenant | The agent's tenant. For SQL, a bound `tenant_id = $n` parameter is required per table, and a parameter naming another tenant is refused |
| Tool | One of `browser`, `http`, `database`, `files`, `shell`, `email`, `github`, `slack`, `mcp`, `cloud`. Anything else, or any malformed call, is itself a blocked, audited event |
| Target | URL, tables, path, command line, recipients, repo@branch, channel, MCP tool, cloud resource |
| Permission | `tool.<family>:read` / `:write` (`tool.shell:execute`), which must be granted *and* within the owner's role; plus delegation when acting for a person |
| Risk | The firewall's deterministic score, plus tool-specific factors and prompt-injection quarantine |
| Destination | `url:…`, `db:…`, `file:…`, `shell:…`, `email:<domains>`, `github:owner/repo`, `slack:<channel>`, `mcp:server/tool`, `cloud:provider:account:region` |

### Blocked, whatever the policy says (hard rules)

| Tool | Examples |
|---|---|
| Browser | Running scripts in a page; typing passwords or card data; executable downloads; `javascript:`, `file:` and internal URLs |
| HTTP | SSRF (internal, metadata, mapped addresses; DNS re-checked at connect time); Host-header overrides; Legion credentials or secrets in the payload |
| Database | Anything other than one SELECT/INSERT/UPDATE/DELETE; DDL, GRANT, COPY; comments; dollar quoting; server/file/network functions; system catalogs; identity/secret/audit tables; UPDATE/DELETE without WHERE; missing or foreign tenant scope |
| Files | Keys, `.env`, `.ssh`, `/proc`; paths outside the roots, including via symlinks (re-checked at the real path); recursive delete; writing executables |
| Shell | Interpreters, privilege tools, network tools, destructive and system commands (`DENIED_COMMANDS`; the policy *can't* allow them); paths or shell strings instead of a bare command; option-based code execution (`git -c`, `--upload-pack`, `core.sshCommand`); shell syntax in arguments; paths leaving the roots. Runs through `execFile` with no shell, a fixed `PATH`, and time and output limits |
| Email | Recipients outside allowed domains; more than `maxRecipients`; choosing the sender; executable attachments; credentials in the message; deleting more than 50 messages |
| GitHub | Merge, delete, visibility, settings, collaborators, deploy keys, secrets, webhooks, branch protection, releases, workflow runs; pushes to protected branches; force pushes; CI/CD and CODEOWNERS changes; secrets in content |
| Slack | Channels not allowlisted or read-only; inviting, creating, archiving, topics; secrets; executable uploads |
| MCP | Unapproved servers or tools; a changed tool definition (pinned SHA-256); undeclared arguments; secrets |
| Cloud | Identity (IAM, STS, SSO, org), logging/detection tampering (CloudTrail, GuardDuty, Config, logs), key management, secret reads, remote command (`ssm:SendCommand`), public exposure (`0.0.0.0/0`, `Principal: "*"`, bucket policies); accounts and regions not allowlisted; destructive actions unless `allowDestructive` |

**Soft rules** block in `enforce` mode and only warn in `monitor` mode:
unlisted hosts or ports, downloads, attachments, Slack mass mentions,
direct messages and uploads, and SQL without a LIMIT.

### Tickets: making "through Legion" enforceable

An allowed call returns a single-use ticket (`ltk_…`, 60 seconds), bound to
the SHA-256 of the exact validated call. A tool server (a service account)
calls `POST /agent/v1/tools/verify { ticket, call }` and runs only on
`valid: true`:
- **Changed arguments** → `call_mismatch`, and the ticket is *not* used up.
- **Second use** → `already_used`.
- **Another tenant** → `unknown`.
- **Expired** → `expired`.

Every verification, accepted or rejected, is audited.

### Executing through Legion

`tools.execute(ctx, call, executor)` runs your executor only after an allow.
Built-in executors:
- `tools.runShell` — `execFile`, no shell
- `tools.files` — symlink-safe
- `tools.http` — via the firewall's egress executor

**Tool output is untrusted content:** it's classified by the prompt-injection
guard, and an injection in a web page, file or API response quarantines the
agent. Outcomes (success, error, output verdict) are appended to the audit.

### Audit (`tool_call_audit`)

- **What's recorded:** every BLOCK and WARN, every high-risk call (state
  changes and external effects, even when allowed), and any call scoring
  at or above `toolSecurity.auditRiskThreshold`.
- **Phases:** `decision`, `outcome`, `ticket_verified`, `ticket_rejected`.
- **Each row holds:**
  - agent, owner, delegated person, tenant
  - tool, operation, target, destination, permission
  - decision, risk score, every rule hit
  - the firewall decision id
  - a digest and redacted preview of the call
  - outcome and output verdict
- **Integrity:** append-only and hash-chained per tenant.
- **Fail closed:** if a risky call can't be audited, it's blocked
  (`tool.audit_unavailable`).

| Endpoint | Who |
|---|---|
| `POST /agent/v1/tools/authorize { call }` | agents |
| `POST /agent/v1/tools/verify { ticket, call }` | service accounts (tool servers) |
| `GET /tools/audit` (filter `decision`, `tool`, `principalId`, `phase`) | admin, analyst |
| `GET /tools/audit/verify` | admin |

Configure through `PUT /firewall/policy` → `toolSecurity`. Everything is
closed by default: no shell commands, email domains, repos, channels or cloud
accounts.

## Runtime behaviour monitoring

**Goal:** notice when an agent behaves differently from its normal role, and
respond in proportion. Not every anomaly is blocked.

### The profile

Each agent's baseline is learned from its **own** firewall decisions. Every
action it took or tried passed the firewall, so that log is its complete
behavioural record.
- **Span:** by default 14 days, excluding the current window, so an attack in
  progress doesn't become "normal".
- **Contents:**
  - actions per active hour (mean, standard deviation, p95)
  - actions and tools used
  - resource types
  - destinations, compared by host, directory or domain set, so a new *path*
    on a known host isn't "new"
  - external destinations and agent peers
  - the people it acts for
  - block rate and share of sensitive requests
  - messages per hour
  - activity by hour of day
- **Storage:** stored, and rebuilt at most hourly.

### What is monitored in the current window (default 60 minutes)

| Dimension | Signals |
|---|---|
| Request volume | Spike; extreme spike |
| Tool usage | Actions never used before; new *unsafe* (state-changing or outward) tools weigh more |
| Accessed resources | Resource types never touched |
| External destinations | One new, several new, fan-out of ten or more (possible exfiltration) |
| Failed operations | Block rate against the baseline; mostly blocked; operations that ran and failed |
| Boundary probing | Many *different* rules stopped it |
| Attack indicators | Cross-tenant attempts, internal addresses, interpreters, protected tables, laundering, public exposure… Counted **even without a baseline** |
| Sensitive data | Any restricted attempt; a rise in confidential access |
| Agent-to-agent | New peers; message bursts; repeated blocks while acting for another agent |
| Changes in normal behaviour | Activity at hours it's never active; acting for new people; malicious external content that reached it |

**Scoring:** the strongest signal per category is summed, capped at 100.
Independent deviations add up; one noisy dimension alone can't reach
CRITICAL.

| Level | Score |
|---|---|
| NORMAL | < 30 |
| SUSPICIOUS | ≥ 30 |
| HIGH_RISK | ≥ 60 |
| CRITICAL | ≥ 85 |

**Agents without a baseline** (fewer than `minBaselineEvents`, or younger than
`minBaselineDays`): "new" means nothing, so novelty isn't counted. Without
intent evidence they're capped at SUSPICIOUS.

### Risk-based enforcement

| Level | Established work | New behaviour | Reads |
|---|---|---|---|
| NORMAL | — | — | — |
| SUSPICIOUS | +5 risk | +10 risk | continue |
| HIGH_RISK | +5 risk, **continues** | unsafe new actions or destinations **held** (`behavior.high_risk_novel_action`), safe ones +25 risk | continue |
| CRITICAL | unsafe actions **contained** (`behavior.critical_containment`) | contained | continue (+40 risk) |

- Every level change is recorded **once**, in the append-only, hash-chained
  `agent_behavior_events`. It's a locked transaction, so concurrent
  assessments across instances can't duplicate it.
- The change reaches `onBehaviorChange` for alerting.
- `autoSuspendOnCritical` (off by default) additionally suspends the
  identity through the kill switch (below), with the same effect as an
  administrator's suspension.
- **An administrator's review** (`POST /behavior/agents/:id/acknowledge`,
  reason required) restarts the window. The admin decides what the reviewed
  activity was:
  - `learn: true` — "this is its role": the activity joins the baseline.
  - `learn: false` — "this was wrong": it's kept out of the baseline.

**If behaviour can't be assessed,** decisions continue on every other rule
with a visible WARN (`behavior.unavailable`).

| Endpoint | Who |
|---|---|
| `GET /behavior/agents` — all agents, worst first | admin, analyst |
| `GET /behavior/agents/:id` — fresh assessment with evidence, and the baseline | admin, analyst |
| `GET /behavior/events`, `/events/verify` | admin, analyst / admin |
| `POST /behavior/agents/:id/acknowledge { reason, learn }` | admin |
| `POST /behavior/sweep` — reassess all active agents now | admin |

Run `identity.behavior.sweep(tenantId)` every minute or so, so levels (and
alerts) update even when an agent goes quiet. Configure with
`PUT /firewall/policy` → `behavior` (`windowMinutes`, `baselineDays`,
`minBaselineEvents`, `minBaselineDays`, `autoSuspendOnCritical`).

## Emergency kill switch

For an agent that is confirmed or strongly suspected to be compromised.

```bash
curl -X POST /kill-switch/agents/<id> -d '{"reason":"Exfiltration to an unknown host","compromise":"suspected"}'
curl -X POST /kill-switch/all -d '{"reason":"…","compromise":"confirmed","confirmAll":true}'   # every AI agent in the org
```

**One transaction** (`KillSwitch.activate`):

1. The identity is marked `suspended`, with the reason.
2. Everything short-lived is withdrawn:
   - access tokens;
   - unused tool tickets;
   - its unexpired requests to other agents (they leave the recipients'
     inboxes, and citing one is refused).
3. On a **confirmed** compromise, its credentials and people's delegations
   are revoked too, so a resume alone does not bring it back: an
   administrator must issue a new credential. On a **suspected** one they
   are kept, so a false alarm is undone with `POST /agents/:id/resume`.
4. An audit row (`killswitch.activated`) is written.
5. A **security event** goes into `security_events` (append-only,
   hash-chained): who, why, how sure, and what was cut off.
6. An **administrator notice** is queued in `security_notifications`.

**Then:**

- **Running tool executions stop.** Those on this instance are aborted
  immediately; other instances abort theirs within `killSwitchPollMs`
  (default 1 s). Shell commands are killed (SIGKILL) and HTTP requests
  cancelled. An executor that ignores the signal is cut loose: its result
  never reaches the agent. Every abort is recorded in `tool_call_audit` with
  outcome `aborted`.
- **The notice is delivered** through `notifyAdmins`. A failure is retried
  with backoff (`killSwitch.deliverPending()`, or
  `POST /kill-switch/notifications/retry`), and two instances never send
  the same notice twice. Without a notifier, the notice is logged as
  `ADMIN NOTICE NOT DELIVERED` and shown as `undeliverable` in the API.
- `onSecurityEvent` fires once per stopped identity, for the SIEM.

**No path around it.** Every way of stopping an identity goes through
`activate()`, so each has exactly the same effect:

- the kill switch;
- an owner's or administrator's `POST /agents/:id/suspend`;
- `POST /agents/:id/revoke`;
- behaviour auto-suspension;
- a library call from, say, a SOAR playbook.

The stop is enforced at every entry point, not only at the one that was
used:

| Path | Enforcement |
|---|---|
| Existing access token, any route (agent API, people's routes, unguarded paths) | Identity status re-checked on every request → 401 |
| Credential → new token | Refused while not active; revoked on confirmed compromise |
| Code holding a principal resolved *before* the stop (agent loops, queued jobs) | The firewall re-reads the status at **every** decision (`identity.not_active`, fails closed) |
| Tool ticket issued before the stop | Revoked; the tool server's verify returns `agent_suspended` |
| Request relayed to another agent | Withdrawn; acting on it is refused (`a2a.message_invalid`) |
| Acting for a person (`x-legion-on-behalf-of`) | Token refused first; confirmed compromise also revokes the grants |
| Execution already running | Aborted (locally at once, other instances within 1 s) |

| Endpoint | Who |
|---|---|
| `POST /kill-switch/agents/:id { reason (≥10 chars), compromise: suspected\|confirmed }` | admin |
| `POST /kill-switch/all { reason, compromise, confirmAll: true }` — every active AI agent (service accounts keep running) | admin |
| `GET /kill-switch/events`, `/events/verify` | admin, analyst / admin |
| `GET /kill-switch/notifications`, `POST /kill-switch/notifications/retry` | admin |

Repeating the switch is harmless: with nothing left to withdraw, it records
nothing. Escalating from suspected to confirmed revokes what remains.
Concurrent activations record exactly one event.

## Agent-to-agent security

An agent asks another agent for work with `POST /agent/v1/messages`. The
recipient reads it from `GET /agent/v1/messages`, and acts on it by citing
it with `x-legion-message-id`. Legion relays and checks every step.

### Every request identifies

| | Set by | Where it shows |
|---|---|---|
| **Source agent** | the sender's token (never the body) | receipt, inbox, log |
| **Destination agent** | `toAgentId`, resolved within the sender's tenant | receipt, inbox, log |
| **Tenant** | the sender's identity; a `tenantId` claim other than its own is refused | receipt, inbox, log |
| **Requested action** | `requestedPermission` (+ optional `resource: {type, id}`) | receipt, inbox, log |
| **Delegated authority** | Legion (below) | receipt, inbox, log, every decision |

Authority is one of:

- `{kind: "agent", agentId, ownerUserId}`: the originating agent's own
  grants, answerable to its owner.
- `{kind: "delegation", userId, grantId, agentId}`: a person's grant to the
  originating agent.

It is fixed when the root request is sent and **travels unchanged down the
chain**. No agent can swap it, top it up, or add a person to it.

### What is prevented

| Threat | Control | Rule |
|---|---|---|
| **Cross-tenant communication** | Recipients are resolved in the sender's tenant only. An agent of another organisation is recorded as a cross-tenant attempt, and the sender learns nothing about it. Message ids of other tenants are unknown. | `a2a.cross_tenant` |
| **Unauthorized delegation** | The pair must be in the policy allowlist (`agentMessages.allow`). Passing a *person's* authority on needs a grant the person marked `redelegable: true`, and only for what they granted. Recipients act under that grant, re-checked at every action, so revoking it voids the request downstream. | `a2a.not_allowlisted`, `a2a.redelegation_not_allowed`, `delegation.not_granted`, `delegation.invalid` |
| **Privilege escalation** | The sender must hold what it asks for. The recipient can do only what was asked, only on the named resource, and only under the request's authority. | `a2a.laundering`, `a2a.message_scope`, `a2a.resource_scope`, `a2a.authority_mismatch` |
| **Unlimited chaining** | Depth (`maxDepth`, default 2, max 4), fan-out per request (`maxFanOut`, 3) and requests per interaction (`maxMessagesPerInteraction`, 10) are limited. There are no cycles or self-messages. A forward never outlives what it forwards. Every agent upstream must still be active; the kill switch withdraws everything downstream of a stopped agent. | `a2a.depth`, `a2a.fan_out`, `a2a.interaction_budget`, `a2a.cycle`, `a2a.chain_member_inactive` |
| **Hidden tool delegation** | See below. | `a2a.hidden_tool_request`, `a2a.hidden_tool_text`, `a2a.hidden_tool_delegation` |

### Hidden tool delegation

Hidden tool delegation means getting another agent to use a tool without
that tool ever appearing in what the firewall checked. It is caught in two
places:

1. **In the request.** The payload is searched for tool calls: Legion's own
   call format, LLM `tool_calls` / `function_call` / `{name, arguments}`,
   MCP `tools/call`, command and SQL objects, and calls serialised as JSON
   strings.
   - A structured call that needs a different permission than the request
     asks for is refused (hard).
   - Tool instructions in prose (command lines, SQL, "execute the script",
     "send … to https://…") are refused too. Set
     `agentMessages.hiddenToolText: "warn"` to allow them with a warning.
   - A tool call asked for openly, with `requestedPermission:
     "tool.slack:write"` and the call as payload, is a normal request.
2. **After the request.** Once an agent has *read* a request, its tool
   calls, MCP calls and egress for `influenceWindowSeconds` (default 900)
   are compared with the request's text. A call whose specific target (a
   channel, host, table, path, command or argument) is named in the request
   must cite the request.
   - If uncited and needing a different permission than the request asked
     for, it is refused and recorded as `hidden_delegation_blocked`.
   - If uncited but the permission matches, it carries a warning
     (`a2a.uncited_request`).

### Interaction chain (`agent_interactions`)

Every step is appended to a hash-chained, append-only log with all five
facts, the agent chain, and the firewall decision. The steps are:

- a request sent or refused;
- a request read;
- an action taken on a request, or refused;
- a hidden delegation stopped.

If a step can't be recorded, the step doesn't happen. Every firewall
decision also carries `agent_chain` and `via_message_id`.

`GET /a2a/interactions/:id` returns the whole investigation for one
interaction:

- the originating agent and authority;
- the tree of requests and forwards;
- every step;
- every firewall decision taken on those requests.

## Agent Trust Graph

`GET /a2a/graph?days=30` shows who may ask whom, for what, on whose
authority, and what actually happened.

- **Nodes:** agents (status, risk, behaviour level, permissions) and people
  (their delegation grants).
- **Edges:** each agent-to-agent pair, with:
  - what the policy declares;
  - what the interaction log shows (sent, refused, read, acted, hidden
    delegation stopped, permissions used, first and last seen);
  - which violations were refused.
- **Edge trust:**
  - `trusted`: declared and used cleanly;
  - `declared_unused`;
  - `broken`: an agent stopped, or the recipient lacks the permission, so
    remove the entry;
  - `undeclared`;
  - `violating`: someone tried to exceed authority over it;
  - `delegated`: a person's grant.
- **Per agent:**
  - `reach`: agents it can reach within `maxDepth`;
  - `canRequest`: what it can get others to do, which is never more than it
    holds.
- **Findings, worst first:**
  - authority violations and cross-tenant attempts;
  - hidden delegation;
  - undeclared traffic;
  - dead allowlist entries;
  - re-delegable grants;
  - HIGH_RISK/CRITICAL agents that still have reach;
  - tampered evidence.

**Why it can be audited:**

- The observed half comes only from the hash-chained interaction log. Its
  integrity is verified on every build and reported in
  `evidence.interactionLog`; a broken chain becomes the top finding.
- The graph carries `graphHash`, the SHA-256 of its canonical JSON, which
  anyone can recompute.
- `POST /a2a/graph/snapshots` freezes the graph in its own hash-chained
  table, so what the graph showed on a given day can be proven later. It is
  admin-only and audited.

| Endpoint | Who |
|---|---|
| `GET /a2a/graph` | admin, analyst |
| `POST /a2a/graph/snapshots { note? }`, `GET /a2a/graph/snapshots/verify` | admin |
| `GET /a2a/graph/snapshots`, `/graph/snapshots/:id` (re-hashed: `intact`) | admin, analyst |
| `GET /a2a/interactions[?agentId=]`, `/interactions/:id` | admin, analyst |
| `GET /a2a/events[?agentId=&kind=]`, `/events/verify` | admin, analyst / admin |

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
   const identity = createAgentIdentity({
     pool, host, exemptPaths: ["/health", "/security-events/webhook", "/billing/webhook"],
     notifyAdmins: (notice) => mailer.sendToTenantAdmins(notice.tenantId, notice.subject, notice), // existing mailer/Slack
   });
   await identity.migrate();                                  // next to the existing migrate()
   app.use(identity.principal);
   app.use("/agent/v1", identity.agentApi);
   app.use("/agents", identity.agents);
   app.use("/service-accounts", identity.serviceAccounts);
   app.use("/audit/principal-events", identity.auditApi);
   app.use("/firewall", identity.firewallApi);
   app.use("/prompt-guard", identity.promptGuardApi);
   app.use("/tools", identity.toolsApi);
   app.use("/behavior", identity.behaviorApi);
   app.use("/kill-switch", identity.killSwitchApi);
   app.use("/a2a", identity.a2aApi);
   setInterval(() => identity.purgeExpiredTokens().catch(() => {}), 3_600_000).unref();
   setInterval(() => identity.killSwitch.deliverPending().catch(() => {}), 60_000).unref();
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
- **Prompt-injection detection can be evaded.** The patterns and statistics
  are English-centric; paraphrased or foreign-language injections, and
  injections split across several fields, can score clean. That's why
  separation and action gating don't depend on detection.
- **The guard can't make a model obey the separation.** It gives the model
  clean, labelled input and stops the dangerous *consequences* (quarantine,
  proposal gating), but a model may still be swayed in what it *says*. Show
  analysts the verdict next to AI answers.
- **Tickets only enforce anything if the tool server checks them.** Tools
  an agent runs itself, without a Legion-verifying server in between, are
  only as safe as the agent's honesty; route them through `tools.execute`
  or a verifying proxy.
- **The SQL reader deliberately accepts a narrow subset.** Valid but
  unusual queries are refused, and a join is accepted only with a
  tenant filter per table (counted, not proven per alias).
- **Browser and HTTP tools require https.** Plain-http sites are refused.
- **Tool-family classification is by name and pattern,** such as cloud
  action names. A provider's new or renamed dangerous action needs adding
  to the list.
- **Behaviour is assessed at most every 30 seconds per agent per instance**
  (`behaviorRefreshSeconds`). A burst inside that interval is classified on
  the next assessment, not mid-burst. Hard firewall rules still apply to
  every single action.
- **A new agent has no baseline for its first days.** It's judged only on
  intent evidence (probing, attack indicators, failures, injected content),
  so a slow, careful misuse by a brand-new agent can pass as "new".
- **Baselines can be poisoned by slow drift.** An agent that shifts its
  behaviour gradually over weeks teaches the baseline as it goes. Periodic
  human review of `GET /behavior/agents/:id` catches what statistics can't.
- **Planted content can quarantine an agent.** An attacker who gets
  malicious text into logs an agent reads can stop its sensitive actions
  until an admin reviews it. That's the conservative trade-off: a stopped
  agent over a hijacked one.
- **People's activity is recorded, not gated.** Content reaching a person's
  Copilot session is recorded against that person, but people are not
  gated by the agent firewall, so it doesn't block their actions.
- **PDFs and documents are classified as extracted text only.** Text hidden
  by PDF styling (white-on-white, off-page) can't be detected from the
  text; the separation still applies.
- **If the injection history can't be read, decisions fail open with a
  visible WARN** (`content.risk_unavailable`) instead of blocking every
  agent.
- **The kill switch stops what passes through Legion.** An agent process
  keeps running on its own host, and anything it does *without* Legion,
  such as a cloud key it was handed directly, is outside this switch. Rotate
  such secrets as part of the incident.
- **An effect already delivered cannot be recalled.** An aborted HTTP
  request may already have reached the server. A custom executor that
  ignores the abort signal may finish its side effect; only its result is
  withheld.
- **Other instances stop running executions within `killSwitchPollMs`**
  (1 s by default), not instantly. New actions are refused everywhere at
  once.
- **Notices depend on the host's `notifyAdmins`.** Without it, notices are
  only logged and listed.
- **Hidden-delegation detection is deterministic, not complete.**
  - Prose detection looks for command lines, SQL and explicit tool
    instructions; a paraphrase ("the usual cleanup") passes.
  - Correlation needs the call's specific target to appear in the request.
    A target that is encoded, or only referred to ("the channel we
    discussed"), is not matched.
  - The underlying protection still holds: whatever the recipient does
    uncited runs on its own permissions and is fully checked and logged.
- **Correlation can hold legitimate work.** An agent that read a request
  naming a host is held for 15 minutes from using a different permission on
  that host uncited. Cite the request, or tune `influenceWindowSeconds`.
- **By default, a tier-2 external action on another agent's request is held
  by the risk score.** A Slack post scores 60, and acting on a request adds
  10, which reaches `blockAt` 70. That is deliberate. Raise `blockAt` to
  allow such delegation.
- **The fan-out and interaction limits are checked, then written.** Two
  forwards at the same instant can exceed a limit by one each.
- **The trust graph re-verifies the whole interaction log on each build.**
  At very large volumes, snapshot periodically rather than building on
  every page view.

## Development

```bash
docker run -d --name legion-test-pg -e POSTGRES_USER=legion -e POSTGRES_PASSWORD=legion-test \
  -e POSTGRES_DB=legion_test -p 127.0.0.1:55432:5432 postgres:16-alpine
npm ci
npm run check && npm test && npm run build
```

Tests use `TEST_DATABASE_URL` (default above) and drop the module's own
tables before each test. Point them at a dedicated database.

### Security assessment

`assessment/` holds a separate, adversarial test suite: 56 live attack
scenarios across prompt injection, tool abuse, permissions, secrets,
tenancy, impersonation, agent-to-agent abuse, behaviour, compromise,
exfiltration, kill-switch bypass, and traditional human-driven attacks.
Each scenario records what actually happened rather than asserting an
expected outcome, so a failure to defend is a finding, not a red test run.

```bash
npx vitest run --config assessment/vitest.config.ts
```

Results: `assessment/results.jsonl` (machine-readable, one row per
scenario). Full write-up with attack path, evidence and recommended fixes:
`../../AI-AGENT-SECURITY-ASSESSMENT-2026-09.md`.
