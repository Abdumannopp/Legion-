import type { Permission } from "../permissions.js";
import type { MachinePrincipal, RiskLevel } from "../types.js";

export type Decision = "ALLOW" | "WARN" | "BLOCK";

/** How sensitive the target is. `restricted` is never reachable by a machine. */
export type Sensitivity = "public" | "internal" | "confidential" | "restricted";
export const SENSITIVITY_ORDER: readonly Sensitivity[] = ["public", "internal", "confidential", "restricted"];

export type Surface = "api" | "file" | "database" | "egress" | "tool" | "mcp_tool" | "agent_message" | "tool_call";

/** Who is asking, and on whose authority. Built by the firewall, never by the caller. */
export interface FirewallContext {
  principal: MachinePrincipal;
  /** A person the agent says it is acting for (x-legion-on-behalf-of). Verified against a delegation grant. */
  onBehalfOf?: string;
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

export interface ApiRequest extends Base { surface: "api" }

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
  effect: "WARN" | "BLOCK";
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
}

/** Optional non-deterministic second opinion (e.g. an LLM). It can only make a decision stricter. */
export type Advisor = {
  name: string;
  review: (ctx: FirewallContext, req: ActionRequest, draft: FirewallDecision) => Promise<"WARN" | "BLOCK" | null>;
};

export interface RiskInputs {
  agentRisk: RiskLevel;
}
