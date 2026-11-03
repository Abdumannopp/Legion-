import type { Permission } from "../permissions.js";
import type { MachinePrincipal, RiskLevel } from "../types.js";

/**
 * What the firewall answers, least to most severe:
 *
 *   ALLOW       run it.
 *   WARN        run it; flagged in the decision log and to the host.
 *   CONFIRM     do not run it until a person approves this exact action
 *               (firewall/approvals.ts). The agent retries citing the approval.
 *   BLOCK       do not run it.
 *   QUARANTINE  do not run it, and suspend the agent (kill switch) before the
 *               answer is returned: its tokens, tool tickets and running
 *               executions are withdrawn until a person reviews it.
 *   KILL        as QUARANTINE, treated as a confirmed compromise: its
 *               credentials and people's delegations are revoked too.
 *
 * Only ALLOW and WARN let an action run; use permits(), never a comparison
 * with a single value, so a new decision can never be read as "not blocked".
 */
export const DECISIONS = ["ALLOW", "WARN", "CONFIRM", "BLOCK", "QUARANTINE", "KILL"] as const;
export type Decision = (typeof DECISIONS)[number];
export type Effect = Exclude<Decision, "ALLOW">;

export const decisionRank = (d: Decision): number => DECISIONS.indexOf(d);

/** True only for decisions that let the action run. Anything else, including an unknown value, refuses. */
export function permits(d: Decision | { decision: Decision }): boolean {
  const v = typeof d === "string" ? d : d.decision;
  return v === "ALLOW" || v === "WARN";
}

/** BLOCK or stricter: the action was refused outright (CONFIRM is not a refusal of the agent, only a wait). */
export function isBlocked(d: Decision | string): boolean {
  const r = DECISIONS.indexOf(d as Decision);
  return r < 0 || r >= DECISIONS.indexOf("BLOCK");
}

/** The rules that stopped an action (every effect stricter than WARN). */
export function refusingHits(d: { hits: RuleHit[] }): RuleHit[] {
  return d.hits.filter((h) => h.effect !== "WARN");
}

/** The API error code for a refusal, so callers can tell "ask a person" from "no". */
export function refusalCode(d: Decision): "approval_required" | "firewall_blocked" | "agent_quarantined" | "agent_killed" {
  return d === "CONFIRM" ? "approval_required" : d === "QUARANTINE" ? "agent_quarantined" : d === "KILL" ? "agent_killed" : "firewall_blocked";
}

/** How sensitive the target is. `restricted` is never reachable by a machine. */
export type Sensitivity = "public" | "internal" | "confidential" | "restricted";
export const SENSITIVITY_ORDER: readonly Sensitivity[] = ["public", "internal", "confidential", "restricted"];

export type Surface = "api" | "file" | "database" | "egress" | "tool" | "mcp_tool" | "agent_message" | "tool_call";

/** Who is asking, and on whose authority. Built by the firewall, never by the caller. */
export interface FirewallContext {
  principal: MachinePrincipal;
  /** A person the agent says it is acting for (x-legion-on-behalf-of). Verified against a delegation grant. */
  onBehalfOf?: string;
  /**
   * A person's approval of this exact action (x-legion-approval-id). It only
   * satisfies CONFIRM rules, only once, and only for the agent and action it
   * was requested for; every other rule is evaluated again.
   */
  approvalId?: string;
  /**
   * Set by Legion's own executors inside an execution whose approval was
   * already consumed, so the nested checks of that same action (the egress
   * request of an approved HTTP call, the write of an approved file call)
   * are not asked again. Never set from anything an agent sends.
   */
  confirmed?: { approvalId: string; decisionId: string };
  /** Agents already in this request's chain, oldest first. Set by Legion from a relayed message, never from a header. */
  chain?: string[];
  /** The relayed agent message this action answers (x-legion-message-id), verified to be addressed to this agent. */
  viaMessage?: RelayedMessage;
  requestId?: string;
  ip?: string;
}

/**
 * Whose authority an agent-to-agent request runs under. Set by Legion when
 * the request is sent and carried unchanged down the chain; never supplied
 * by an agent.
 *  - agent: the originating agent's own grants (answerable to its owner);
 *  - delegation: a person's delegation grant to the originating agent,
 *    which that person marked as re-delegable.
 */
export type Authority =
  | { kind: "agent"; agentId: string; ownerUserId: string }
  | { kind: "delegation"; userId: string; grantId: string; agentId: string };

/** A relayed request, as Legion stored it. */
export interface RelayedMessage {
  id: string;
  fromAgentId: string;
  permission: Permission;
  /** Agents before the sender, oldest first. */
  chain: string[];
  /** The root request's id: one interaction, however far it is forwarded. */
  interactionId: string;
  hop: number;
  authority: Authority;
  /** The one resource the request is about, if it named one. */
  resource: { type: string; id: string } | null;
  expiresAt: string;
}

export interface ResourceTarget {
  type: string;
  id?: string;
  /** Tenant the resource belongs to, when the caller knows it. Must equal the agent's. */
  tenantId?: string;
}

interface Base {
  /** Name of the action, e.g. "alerts:update_status", "files:read", "tool:send_email". */
  action: string;
  /** Permission the action needs. null = a self-service action needing none (whoami). */
  permission: Permission | null;
  resource?: ResourceTarget;
  sensitivity?: Sensitivity;
}

export interface ApiRequest extends Base {
  surface: "api";
  /** What the call carries (method, path, body): part of the digest an approval is bound to. */
  input?: unknown;
}

export interface FileRequest extends Base {
  surface: "file";
  path: string;
  mode: "read" | "write";
}

export type DbOperation = "select" | "insert" | "update" | "delete" | "ddl" | "raw";
export interface DatabaseRequest extends Base {
  surface: "database";
  table: string;
  operation: DbOperation;
  /** Upper bound on rows read or changed. */
  rowLimit: number;
  /** The tenant the query is filtered to. Must be the agent's own. */
  tenantFilter: string | null;
}

export interface EgressRequest extends Base {
  surface: "egress";
  url: string;
  method: string;
  /** Body or payload leaving Legion, scanned for secrets. */
  payload?: unknown;
}

export interface ToolRequest extends Base {
  surface: "tool";
  tool: string;
  args: Record<string, unknown>;
}

export interface McpToolRequest extends Base {
  surface: "mcp_tool";
  server: string;
  tool: string;
  /** sha256 of the tool definition the server advertises right now (hashToolDefinition). */
  definitionSha256: string;
  /**
   * The definition itself, when the caller has it. Its descriptions are
   * scanned for instructions aimed at the model (tool poisoning), and its
   * hash must equal definitionSha256.
   */
  definition?: { name: string; description?: string; inputSchema?: unknown };
  args: Record<string, unknown>;
}

export interface AgentMessageRequest extends Base {
  surface: "agent_message";
  toAgentId: string;
  /** The permission the recipient will exercise because of this message. */
  requestedPermission: Permission;
  /** Optional: the one resource the recipient may act on under this request. */
  requestResource?: { type: string; id: string };
  /** The tenant the sender says the recipient is in. Must be the sender's own. */
  claimedTenantId?: string;
  payload?: unknown;
}

/**
 * A tool call already analysed by the tool gateway (src/tools). The analysis
 * is computed by Legion from the call; callers never supply it.
 */
export interface ToolCallRequest extends Base {
  surface: "tool_call";
  toolKind: string;
  operation: string;
  target: string;
  destination: string;
  changesState: boolean;
  externalEffect: boolean;
  analysisHits: RuleHit[];
  analysisFactors: RiskFactor[];
  /** The call itself, for the input digest and redacted preview in the decision log. */
  call: unknown;
}

export type ActionRequest =
  | ToolCallRequest
  | ApiRequest
  | FileRequest
  | DatabaseRequest
  | EgressRequest
  | ToolRequest
  | McpToolRequest
  | AgentMessageRequest;

/** One rule that matched. `hard` rules can never be relaxed by mode, policy or an advisor. */
export interface RuleHit {
  id: string;
  effect: Effect;
  hard: boolean;
  reason: string;
}

export interface RiskFactor {
  factor: string;
  points: number;
}

export interface FirewallDecision {
  decisionId: string;
  decision: Decision;
  /** In monitor mode, soft blocks become WARN; this records that it would have blocked. */
  wouldBlock: boolean;
  mode: "enforce" | "monitor";
  riskScore: number;
  riskFactors: RiskFactor[];
  hits: RuleHit[];
  policyVersion: number;
  /** Normalised destination, when the action leaves Legion or touches a path/table. */
  destination: string | null;
  sensitivity: Sensitivity;
  delegation: { userId: string; grantId: string } | null;
  advisor: { name: string; verdict: "WARN" | "BLOCK" | null; error?: string }[];
  /** CONFIRM: the approval a person must grant (or the one that was used). */
  approval?: { id: string; status: "pending" | "consumed"; expiresAt: string; approvedBy?: string } | null;
  /** QUARANTINE / KILL: the containment applied before this decision was returned. */
  response?: { action: "quarantine" | "kill"; applied: boolean; error?: string } | null;
}

/** Optional non-deterministic second opinion (e.g. an LLM). It can only make a decision stricter. */
export type Advisor = {
  name: string;
  review: (ctx: FirewallContext, req: ActionRequest, draft: FirewallDecision) => Promise<"WARN" | "BLOCK" | null>;
};

export interface RiskInputs {
  agentRisk: RiskLevel;
}
