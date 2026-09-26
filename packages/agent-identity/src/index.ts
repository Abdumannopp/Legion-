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
  const agentBasePath = opts.agentBasePath ?? "/agent/v1";
  const sampler = new FailureSampler();
  const deps = { store, audit, host: opts.host, guards, sampler, log, firewall, policies, decisions, delegations, contentGuard };
  const agentExtras = Router();
  agentExtras.use(agentMessageRouter(deps));
  agentExtras.use(contentInspectRouter(deps));

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
    guards,
    audit,
    firewall,
    /** Classify, record and wrap external content before any model reads it. */
    contentGuard,
    /** Call periodically (e.g. hourly) to drop long-expired token rows. */
    purgeExpiredTokens: () => store.purgeExpiredTokens(),
  };
}

export type AgentIdentity = ReturnType<typeof createAgentIdentity>;
