import type { Pool } from "pg";
import { AuditLog } from "./audit.js";
import { createGuards } from "./authorize.js";
import { createPrincipalResolver, DEFAULT_AI_USER_AGENTS, FailureSampler } from "./principal.js";
import { agentRouter } from "./routes/agent.js";
import { auditRouter, managementRouter } from "./routes/management.js";
import { migrate } from "./schema.js";
import { IdentityStore } from "./store.js";
import type { HostAdapter } from "./types.js";

export * from "./types.js";
export * from "./permissions.js";
export type { AuditEvent, AuditOutcome, AuditRow } from "./audit.js";
export type { Identity, CredentialInfo } from "./store.js";
export { DEFAULT_AI_USER_AGENTS } from "./principal.js";
export { TOKEN_TTL_SECONDS } from "./routes/agent.js";

export interface AgentIdentityOptions {
  pool: Pool;
  host: HostAdapter;
  /** Default "/agent/v1". */
  agentBasePath?: string;
  /** Paths that skip principal resolution entirely. Default ["/health"]. */
  exemptPaths?: string[];
  /** Self-declared AI user agents that must authenticate. null disables the check. */
  aiUserAgents?: RegExp | null;
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
 *   app.use("/agent/v1", identity.agentApi);      // agents: token, whoami
 *   app.use("/agents", identity.agents);          // people: manage AI agents
 *   app.use("/service-accounts", identity.serviceAccounts);
 *   app.use("/audit/principal-events", identity.auditApi);
 *   app.get("/agent/v1/alerts", identity.guards.requirePermission("alerts:read"), handler);
 */
export function createAgentIdentity(opts: AgentIdentityOptions) {
  const log = opts.log ?? ((msg: string, err?: unknown) => console.warn(`[agent-identity] ${msg}`, err ?? ""));
  const store = new IdentityStore(opts.pool);
  const audit = new AuditLog(opts.pool);
  const guards = createGuards(audit, log);
  const agentBasePath = opts.agentBasePath ?? "/agent/v1";
  const sampler = new FailureSampler();
  const deps = { store, audit, host: opts.host, guards, sampler, log };

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
      },
    }),
    agentApi: agentRouter(deps),
    agents: managementRouter("ai_agent", deps),
    serviceAccounts: managementRouter("service_account", deps),
    auditApi: auditRouter(deps),
    guards,
    audit,
    /** Call periodically (e.g. hourly) to drop long-expired token rows. */
    purgeExpiredTokens: () => store.purgeExpiredTokens(),
  };
}

export type AgentIdentity = ReturnType<typeof createAgentIdentity>;
