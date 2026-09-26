import type { Pool } from "pg";
import { AuditLog } from "./audit.js";
import { createGuards } from "./authorize.js";
import { DelegationStore } from "./firewall/delegations.js";
import { AgentFirewall } from "./firewall/engine.js";
import { DecisionLog } from "./firewall/log.js";
import { PolicyStore } from "./firewall/policy.js";
import { agentMessageRouter, firewallAdminRouter } from "./firewall/routes.js";
import type { ActionRequest, Advisor, FirewallContext, FirewallDecision } from "./firewall/types.js";
import { createPrincipalResolver, DEFAULT_AI_USER_AGENTS, FailureSampler } from "./principal.js";
import { PromptInjectionGuard } from "./prompt-guard/guard.js";
import { contentInspectRouter, promptGuardAdminRouter } from "./prompt-guard/routes.js";
import { ToolGateway } from "./tools/gateway.js";
import { toolAdminRouter, toolAgentRouter } from "./tools/routes.js";
import { BehaviorMonitor, type BehaviorChange } from "./behavior/monitor.js";
import { behaviorAdminRouter } from "./behavior/routes.js";
import { KillSwitch, type AdminNotice, type SecurityEventRow } from "./killswitch/service.js";
import { killSwitchRouter } from "./killswitch/routes.js";
import { Router } from "express";
import { agentRouter } from "./routes/agent.js";
import { auditRouter, managementRouter } from "./routes/management.js";
import { migrate } from "./schema.js";
import { IdentityStore } from "./store.js";
import { isMachine, type HostAdapter } from "./types.js";

export * from "./types.js";
export * from "./permissions.js";
export type { AuditEvent, AuditOutcome, AuditRow } from "./audit.js";
export type { Identity, CredentialInfo } from "./store.js";
export type * from "./firewall/types.js";
export type { FirewallPolicy } from "./firewall/policy.js";
export type { DecisionRow } from "./firewall/log.js";
export { DEFAULT_AI_USER_AGENTS } from "./principal.js";
export { TOKEN_TTL_SECONDS } from "./routes/agent.js";
export { AgentFirewall, FirewallBlockedError } from "./firewall/engine.js";
export { DEFAULT_POLICY, PROTECTED_TABLES, policySchema } from "./firewall/policy.js";
export { hashToolDefinition } from "./firewall/scan.js";
export { evaluateRules } from "./firewall/rules.js";
export { PromptInjectionGuard, RecordedAssembly, type IngestContext, type IngestResult } from "./prompt-guard/guard.js";
export { PromptAssembly, SYSTEM_PROMPTS, reviewProposedAction, type SystemPromptId, type PromptMessage, type ProposedAction, type ProposalReview } from "./prompt-guard/assembly.js";
export { classifyContent } from "./prompt-guard/detectors.js";
export type * from "./prompt-guard/types.js";
export { CONTENT_SOURCES, THRESHOLDS } from "./prompt-guard/types.js";
export { ToolGateway, ToolBlockedError, callDigest, type ToolAuthorization, type ToolResult } from "./tools/gateway.js";
export { analyzeToolCall } from "./tools/analyzers.js";
export { TOOL_KINDS, toolCallSchema, type ToolCall, type ToolCallInput, type ToolKind, type ToolAnalysis } from "./tools/types.js";
export { DENIED_COMMANDS } from "./tools/shell.js";
export type { ToolAuditRow } from "./tools/audit.js";
export { BehaviorMonitor, type BehaviorChange, type BehaviorState, type BehaviorEventRow } from "./behavior/monitor.js";
export { assess, isAttackIndicator, isUnsafeAction } from "./behavior/assess.js";
export { destinationKey, ATTACK_INDICATORS } from "./behavior/keys.js";
export { KillSwitch, severityOf, type AdminNotice, type Compromise, type KillSwitchResult, type NotificationStatus, type SecurityEventKind, type SecurityEventRow, type Severity } from "./killswitch/service.js";
export { ToolAbortedError } from "./tools/gateway.js";
export type { CutOff } from "./store.js";
export { levelOf, LEVEL_THRESHOLDS, LEVEL_ORDER, type BehaviorLevel, type Assessment, type BehaviorProfile, type Signal } from "./behavior/types.js";

export interface AgentIdentityOptions {
  pool: Pool;
  host: HostAdapter;
  /** Default "/agent/v1". Machine identities are confined to this prefix. */
  agentBasePath?: string;
  /** Paths that skip principal resolution entirely. Default ["/health"]. */
  exemptPaths?: string[];
  /** Self-declared AI user agents that must authenticate. null disables the check. */
  aiUserAgents?: RegExp | null;
  /** Optional non-deterministic reviewers (e.g. an LLM). They can only escalate a decision. */
  firewallAdvisors?: Advisor[];
  /** Called for every WARN/BLOCK after it is logged — hook this to Legion's alerting. */
  onFirewallDecision?: (ctx: FirewallContext, req: ActionRequest, d: FirewallDecision) => void | Promise<void>;
  /** DNS resolver for firewall.request(); every returned address is checked. */
  dnsLookup?: (host: string) => Promise<{ address: string; family: number }[]>;
  /** Called once when an agent's behaviour level changes — hook this to Legion's alerting. */
  onBehaviorChange?: (change: BehaviorChange) => void | Promise<void>;
  /** How long a per-agent behaviour assessment is reused (default 30 s). */
  behaviorRefreshSeconds?: number;
  /**
   * Delivers a kill-switch / suspension notice to the tenant's
   * administrators (email, Slack, pager…). Throw to have it retried.
   * Without it, notices are logged and kept in the API as undeliverable.
   */
  notifyAdmins?: (notice: AdminNotice) => void | Promise<void>;
  /** Called once per security event (suspension, revocation, kill switch) — hook this to Legion's alerting/SIEM. */
  onSecurityEvent?: (event: Omit<SecurityEventRow, "seq">) => void | Promise<void>;
  /** How often running tool executions re-check their agent's status (default 1000 ms). */
  killSwitchPollMs?: number;
  log?: (msg: string, err?: unknown) => void;
}

/**
 * Wiring (see README.md):
 *
 *   const identity = createAgentIdentity({ pool, host });
 *   await identity.migrate();
 *   app.use(cookieParser());
 *   app.use(express.json());
 *   app.use(identity.principal);                  // every request gets req.principal
 *   app.use("/agent/v1", identity.agentApi);      // agents: token, whoami, messages
 *   app.use("/agents", identity.agents);          // people: manage AI agents
 *   app.use("/service-accounts", identity.serviceAccounts);
 *   app.use("/audit/principal-events", identity.auditApi);
 *   app.use("/firewall", identity.firewallApi);   // people: policy, decisions, delegations
 *   app.use("/prompt-guard", identity.promptGuardApi); // people: injection events, acknowledge
 *   app.use("/tools", identity.toolsApi);        // people: tool audit log
 *   app.use("/behavior", identity.behaviorApi);  // people: agent behaviour, review
 *   app.use("/kill-switch", identity.killSwitchApi); // admins: emergency stop, security events
 *   app.get("/agent/v1/alerts", identity.guards.requirePermission("alerts:read"), handler);
 */
export function createAgentIdentity(opts: AgentIdentityOptions) {
  const log = opts.log ?? ((msg: string, err?: unknown) => console.warn(`[agent-identity] ${msg}`, err ?? ""));
  const store = new IdentityStore(opts.pool);
  const audit = new AuditLog(opts.pool);
  const policies = new PolicyStore(opts.pool);
  const decisions = new DecisionLog(opts.pool);
  const delegations = new DelegationStore(opts.pool);
  const contentGuard = new PromptInjectionGuard(opts.pool, log);
  const firewall = new AgentFirewall({
    pool: opts.pool,
    store,
    host: opts.host,
    policies,
    decisions,
    delegations,
    advisors: opts.firewallAdvisors,
    onDecision: opts.onFirewallDecision,
    dnsLookup: opts.dnsLookup,
    contentGuard,
    log,
  });
  const guards = createGuards(audit, log, firewall);
  const tools = new ToolGateway({ pool: opts.pool, firewall, policies, contentGuard, log, statusPollMs: opts.killSwitchPollMs });
  const behavior = new BehaviorMonitor({
    pool: opts.pool, policies, store, audit, contentGuard, log,
    onChange: opts.onBehaviorChange, refreshSeconds: opts.behaviorRefreshSeconds,
  });
  firewall.setBehaviorMonitor(behavior);
  const killSwitch = new KillSwitch({
    pool: opts.pool, store, audit, tools, behavior, log, notifyAdmins: opts.notifyAdmins, onSecurityEvent: opts.onSecurityEvent,
  });
  behavior.setSuspender(async (tenantId, identityId, actor, reason) => {
    const r = await killSwitch.activate({ tenantId, identityIds: [identityId], reason, compromise: "suspected", actor, kind: "agent_auto_suspended" });
    return r.affected.length > 0;
  });
  const agentBasePath = opts.agentBasePath ?? "/agent/v1";
  const sampler = new FailureSampler();
  const deps = { store, audit, host: opts.host, guards, sampler, log, firewall, policies, decisions, delegations, contentGuard, tools, behavior, killSwitch };
  const agentExtras = Router();
  agentExtras.use(agentMessageRouter(deps));
  agentExtras.use(contentInspectRouter(deps));
  agentExtras.use(toolAgentRouter(deps));

  // Safety net: a machine request that completed without a firewall decision
  // means a route was added without a guard. It is recorded as a failure so
  // it shows up in the audit trail and the logs.
  const flagUnguarded = (req: import("express").Request, res: import("express").Response) => {
    if (req.firewallDecision || !isMachine(req.principal)) return;
    log(`UNGUARDED agent route: ${req.method} ${req.path} completed without a firewall decision`);
    audit
      .record({
        principal: req.principal,
        action: "firewall.unguarded_route",
        outcome: "failure",
        reason: "agent request completed without a firewall decision",
        requestId: req.requestId,
        details: { method: req.method, path: req.path, status: res.statusCode },
      })
      .catch((err) => log("audit write failed for an unguarded route", err));
  };

  return {
    migrate: () => migrate(opts.pool),
    principal: createPrincipalResolver({
      store,
      audit,
      host: opts.host,
      sampler,
      log,
      options: {
        agentBasePath,
        exemptPaths: opts.exemptPaths ?? ["/health"],
        aiUserAgents: opts.aiUserAgents === undefined ? DEFAULT_AI_USER_AGENTS : opts.aiUserAgents,
        confineMachinesTo: [agentBasePath],
        onMachineRequestFinished: flagUnguarded,
      },
    }),
    agentApi: agentRouter({ ...deps, extra: agentExtras }),
    agents: managementRouter("ai_agent", deps),
    serviceAccounts: managementRouter("service_account", deps),
    auditApi: auditRouter(deps),
    firewallApi: firewallAdminRouter(deps),
    promptGuardApi: promptGuardAdminRouter(deps),
    toolsApi: toolAdminRouter(deps),
    behaviorApi: behaviorAdminRouter(deps),
    killSwitchApi: killSwitchRouter(deps),
    guards,
    audit,
    firewall,
    /** Classify, record and wrap external content before any model reads it. */
    contentGuard,
    /** Every AI tool call passes here: authorize, execute safely, audit. */
    tools,
    /** Behavioural profiles and runtime classification. Run behavior.sweep(tenantId) every minute. */
    behavior,
    /** Emergency stop for agents. Run killSwitch.deliverPending() every minute to retry admin notices. */
    killSwitch,
    /** Call periodically (e.g. hourly) to drop long-expired token and tool-ticket rows. */
    purgeExpiredTokens: async () => (await store.purgeExpiredTokens()) + (await tools.purgeExpiredTickets()),
  };
}

export type AgentIdentity = ReturnType<typeof createAgentIdentity>;
