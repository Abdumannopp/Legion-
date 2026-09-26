import { PERMISSION_TIERS, roleAllows, type Permission } from "../permissions.js";
import type { HumanRole, MachinePrincipal } from "../types.js";
import { classifyUrl } from "./destinations.js";
import { checkFilePath } from "./paths.js";
import { PROTECTED_TABLES, type FirewallPolicy } from "./policy.js";
import { byteSize, findSecrets, findUrls } from "./scan.js";
import type { ContentRiskSummary, Verdict } from "../prompt-guard/types.js";
import type { BehaviorState } from "../behavior/monitor.js";
import { destinationKey } from "../behavior/keys.js";
import { SENSITIVITY_ORDER, type ActionRequest, type RiskFactor, type RuleHit, type Sensitivity } from "./types.js";

/** Facts the engine looked up before evaluation. The rules never do I/O. */
export interface RuleInputs {
  principal: MachinePrincipal;
  req: ActionRequest;
  policy: FirewallPolicy;
  delegation:
    | { state: "none" }
    | { state: "invalid"; userId: string; reason: string }
    | { state: "valid"; userId: string; grantId: string; userRole: HumanRole; permissions: Permission[] };
  /** Agent-to-agent: the addressed agent, as found in this tenant. */
  recipient?:
    | { state: "missing" }
    | { state: "blocked"; reason: string }
    | { state: "ok"; id: string; effectivePermissions: Permission[] };
  /** A message this action claims to act on (x-legion-message-id), already verified to be addressed here. */
  viaMessage?: { id: string; fromAgentId: string; permission: Permission; senderActive: boolean };
  chain: string[];
  actionsLastMinute: number;
  /**
   * Flagged external content that reached this agent and no person has
   * reviewed yet, or "unavailable" if it could not be looked up.
   */
  contentRisk?: ContentRiskSummary | "unavailable";
  /** Agent-to-agent: how the message payload classifies as external content. */
  payloadClassification?: { verdict: Verdict; riskScore: number; findingIds: string[] };
  /** Runtime behaviour classification, or "unavailable" if it could not be assessed. */
  behavior?: BehaviorState | "unavailable";
  /**
   * The identity as stored right now (null: no such identity). The
   * principal may have been resolved earlier — a long-running agent loop, a
   * queued job — so its status is re-read at every decision.
   */
  live?: { status: string; riskLevel: string; expired: boolean } | null;
}

export interface RuleOutput {
  hits: RuleHit[];
  factors: RiskFactor[];
  permission: Permission | null;
  sensitivity: Sensitivity;
  destination: string | null;
}

const TABLE_NAME = /^[a-z_][a-z0-9_]{0,62}$/;
const HTTP_METHODS = new Set(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]);

const maxSensitivity = (...levels: (Sensitivity | undefined)[]): Sensitivity =>
  levels.reduce<Sensitivity>(
    (acc, s) => (s && SENSITIVITY_ORDER.indexOf(s) > SENSITIVITY_ORDER.indexOf(acc) ? s : acc),
    "public",
  );

export function evaluateRules(input: RuleInputs): RuleOutput {
  const { principal: p, req, policy } = input;
  const hits: RuleHit[] = [];
  const factors: RiskFactor[] = [];
  const hard = (id: string, reason: string) => hits.push({ id, effect: "BLOCK", hard: true, reason });
  const soft = (id: string, reason: string) => hits.push({ id, effect: "BLOCK", hard: false, reason });
  const warn = (id: string, reason: string) => hits.push({ id, effect: "WARN", hard: false, reason });
  const add = (factor: string, points: number) => points && factors.push({ factor, points });

  let permission: Permission | null = req.permission;
  let destination: string | null = null;
  let sensitivity = maxSensitivity("internal", req.sensitivity, req.resource ? policy.resources[req.resource.type] : undefined);
  let externalEffect = false;
  let changesState = false;

  // ---- Surface-specific checks --------------------------------------------
  const checkArgs = (spec: { allowedArgs?: string[]; maxArgBytes: number; sideEffects: string }, args: Record<string, unknown>, label: string) => {
    if (spec.allowedArgs) {
      const extra = Object.keys(args).filter((k) => !spec.allowedArgs!.includes(k));
      if (extra.length) hard(`${label}.unexpected_args`, `Arguments not declared for this tool: ${extra.join(", ")}`);
    }
    if (byteSize(args) > spec.maxArgBytes) hard(`${label}.args_too_large`, `Arguments exceed ${spec.maxArgBytes} bytes.`);
    const secrets = findSecrets(args);
    if (secrets.length) hard(`${label}.secret_in_args`, `Arguments contain credentials (${secrets.join(", ")}).`);
    if (spec.sideEffects === "external") {
      externalEffect = true;
      for (const url of findUrls(args)) {
        const v = classifyUrl(url, policy.egress.allowedHosts, policy.egress.allowedPorts);
        if (!v.ok) (v.hard ? hard : soft)(`${label}.${v.rule}`, `${url}: ${v.reason}`);
      }
    }
  };

  switch (req.surface) {
    case "api":
      destination = `api:${req.resource?.type ?? req.action}`;
      break;

    case "file": {
      const v = checkFilePath(policy, req.path, req.mode);
      destination = v.destination;
      for (const pr of v.problems) hard(pr.id, pr.reason);
      if (req.mode === "write") {
        add("file write", 10);
        changesState = true;
      }
      break;
    }

    case "database": {
      const table = req.table.toLowerCase();
      destination = `db:${table}`;
      if (req.operation === "ddl" || req.operation === "raw") {
        hard("db.raw_or_ddl", "Agents cannot run raw SQL or change the schema.");
      }
      if (!TABLE_NAME.test(table) || table.startsWith("pg_") || table.includes("information_schema")) {
        hard("db.bad_table", "Not a valid application table name.");
      } else if (PROTECTED_TABLES.has(table)) {
        hard("db.protected_table", `${table} holds identities, secrets or audit history.`);
      } else {
        const allowed = policy.database.tables[table];
        if (!allowed) hard("db.table_not_allowed", `${table} is not opened to agents by this organisation's policy.`);
        else if (!allowed.includes(req.operation as never)) hard("db.operation_not_allowed", `${req.operation} on ${table} is not allowed.`);
      }
      if (req.tenantFilter !== p.tenantId) hard("db.tenant_filter", "Every query must be restricted to the agent's own organisation.");
      if (!Number.isInteger(req.rowLimit) || req.rowLimit < 1) hard("db.row_limit_missing", "A positive row limit is required.");
      else if (req.rowLimit > policy.database.maxRows) soft("db.row_limit", `Row limit ${req.rowLimit} exceeds ${policy.database.maxRows}.`);
      add(`db ${req.operation}`, req.operation === "delete" ? 20 : req.operation === "select" ? 0 : 10);
      if (req.operation !== "select") changesState = true;
      break;
    }

    case "egress": {
      externalEffect = true;
      const method = req.method.toUpperCase();
      if (!HTTP_METHODS.has(method)) hard("egress.method", `HTTP method ${req.method} is not allowed.`);
      const v = classifyUrl(req.url, policy.egress.allowedHosts, policy.egress.allowedPorts);
      destination = v.normalized ? `url:${v.normalized}` : "url:(invalid)";
      if (!v.ok) (v.hard ? hard : soft)(v.rule, v.reason);
      const secrets = findSecrets(req.payload);
      if (secrets.length) hard("egress.secret_in_payload", `Outgoing data contains credentials (${secrets.join(", ")}).`);
      sensitivity = maxSensitivity(sensitivity, "confidential"); // data leaving the organisation
      break;
    }

    case "tool": {
      destination = `tool:${req.tool}`;
      const spec = policy.tools[req.tool];
      if (!spec) {
        hard("tool.unknown", `Tool ${req.tool} is not registered in this organisation's policy.`);
        break;
      }
      permission = spec.permission; // the policy, not the caller, says what the tool needs
      sensitivity = maxSensitivity(sensitivity, spec.sensitivity);
      checkArgs(spec, req.args, "tool");
      break;
    }

    case "mcp_tool": {
      destination = `mcp:${req.server}/${req.tool}`;
      const server = policy.mcp.servers[req.server];
      const spec = server?.tools[req.tool];
      if (!server) hard("mcp.unknown_server", `MCP server ${req.server} is not approved.`);
      else if (!spec) hard("mcp.unknown_tool", `MCP tool ${req.tool} is not approved on ${req.server}.`);
      else if (spec.sha256 !== req.definitionSha256) {
        hard("mcp.definition_changed",
          "The tool's advertised definition no longer matches the approved one (possible tool poisoning). Review and re-approve it.");
      }
      if (!spec) break;
      permission = spec.permission;
      sensitivity = maxSensitivity(sensitivity, spec.sensitivity);
      checkArgs(spec, req.args, "mcp");
      break;
    }

    case "tool_call": {
      destination = req.destination;
      hits.push(...req.analysisHits);
      factors.push(...req.analysisFactors);
      if (req.changesState) changesState = true;
      if (req.externalEffect) externalEffect = true;
      break;
    }

    case "agent_message": {
      destination = `agent:${req.toAgentId}`;
      permission = null; // sending needs no permission; what the message asks for is checked below
      const hops = input.chain.length + 1;
      if (req.toAgentId === p.id) hard("a2a.self", "An agent cannot message itself.");
      if (input.chain.includes(req.toAgentId)) hard("a2a.cycle", "The recipient is already in this chain of agents.");
      if (hops > policy.agentMessages.maxDepth) hard("a2a.depth", `Chain of ${hops} agent hops exceeds ${policy.agentMessages.maxDepth}.`);
      const r = input.recipient;
      if (!r || r.state === "missing") hard("a2a.recipient_unknown", "No such agent in this organisation.");
      else if (r.state === "blocked") hard("a2a.recipient_unavailable", `Recipient cannot act: ${r.reason}.`);
      else if (!r.effectivePermissions.includes(req.requestedPermission)) {
        hard("a2a.recipient_lacks_permission", `The recipient does not hold ${req.requestedPermission}.`);
      }
      // No laundering: an agent cannot get another agent to do what it may not do itself.
      if (!p.permissions.includes(req.requestedPermission)) {
        hard("a2a.laundering", `The sender does not hold ${req.requestedPermission} itself.`);
      }
      const allowed = policy.agentMessages.allow.some(
        (a) => a.from === p.id && a.to === req.toAgentId && (!a.permissions || a.permissions.includes(req.requestedPermission)),
      );
      if (!allowed) soft("a2a.not_allowlisted", "This pair of agents is not allowed to talk in this organisation's policy.");
      const secrets = findSecrets(req.payload);
      if (secrets.length) hard("a2a.secret_in_payload", `The message contains credentials (${secrets.join(", ")}).`);
      if (byteSize(req.payload) > 16_384) hard("a2a.payload_too_large", "Messages are limited to 16 KB.");
      add("agent-to-agent hop", 5 * hops);
      const tier = PERMISSION_TIERS[req.requestedPermission];
      add(`requested permission tier ${tier}`, tier * 10);
      break;
    }
  }

  // ---- Checks every surface shares ----------------------------------------
  if (p.type !== "ai_agent" && p.type !== "service_account") hard("identity.not_machine", "Only registered machine identities pass this firewall.");
  if (p.riskLevel === "critical") hard("identity.risk_hold", "This identity is on risk hold.");
  if (input.live !== undefined) {
    const l = input.live;
    if (!l) hard("identity.not_active", "This identity no longer exists.");
    else if (l.status !== "active") hard("identity.not_active", `This identity is ${l.status}.`);
    else if (l.expired) hard("identity.not_active", "This identity has expired.");
    else if (l.riskLevel === "critical" && p.riskLevel !== "critical") hard("identity.risk_hold", "This identity is on risk hold.");
  }
  if (req.resource?.tenantId && req.resource.tenantId !== p.tenantId) {
    hard("tenant.mismatch", "The target belongs to another organisation.");
  }
  if (permission && !p.permissions.includes(permission)) {
    hard("permission.not_granted", `The agent does not hold ${permission} (or its owner's role no longer allows it).`);
  }
  if (sensitivity === "restricted") hard("sensitivity.restricted", "Restricted data is never available to machine identities.");

  const d = input.delegation;
  if (d.state === "invalid") hard("delegation.invalid", `Cannot act for ${d.userId}: ${d.reason}.`);
  if (d.state === "valid") {
    add("acting for a person", 5);
    if (permission && !d.permissions.includes(permission)) hard("delegation.not_granted", `${d.userId} did not delegate ${permission}.`);
    else if (permission && !roleAllows(d.userRole, permission)) hard("delegation.exceeds_user", `${d.userId}'s role does not allow ${permission}.`);
  }

  const m = input.viaMessage;
  if (m) {
    if (!m.senderActive) hard("a2a.sender_inactive", "The agent that sent this request can no longer act.");
    // Acting on a message: the action must be what the message asked for.
    // Forwarding it to another agent: the forward must ask for the same thing.
    const scoped = req.surface === "agent_message" ? req.requestedPermission : permission;
    if (scoped !== m.permission) hard("a2a.message_scope", `The message only asked for ${m.permission}.`);
    add("acting on another agent's request", 10);
  }

  // ---- Prompt injection -------------------------------------------------------
  // Malicious external content reached this agent and nobody has reviewed
  // it: the agent may be acting on an attacker's instructions. Reading stays
  // possible (with higher risk); anything that changes state, acts outside
  // Legion, touches confidential data or messages other agents is blocked
  // until a person acknowledges the event.
  const tier = permission ? PERMISSION_TIERS[permission] : 0;
  const unsafe =
    tier >= 2 || changesState || externalEffect || req.surface === "agent_message" ||
    sensitivity === "confidential" || sensitivity === "restricted";
  const cr = input.contentRisk;
  if (cr === "unavailable") {
    warn("content.risk_unavailable", "Could not check for recent prompt-injection events.");
  } else if (cr && cr.unacknowledgedMalicious > 0) {
    add("unreviewed malicious external content", 40);
    if (unsafe) {
      hard("content.quarantine",
        `${cr.unacknowledgedMalicious} malicious external content event(s) reached this agent and have not been reviewed. ` +
        "An administrator must review and acknowledge them before it can take sensitive actions.");
    }
  } else if (cr && cr.unacknowledgedSuspicious > 0) {
    add("recent suspicious external content", Math.min(25, 10 + 5 * (cr.unacknowledgedSuspicious - 1)));
  }

  // ---- Runtime behaviour (risk-based, not block-everything) ---------------------
  // SUSPICIOUS only raises risk. HIGH_RISK blocks unsafe actions that are
  // also NEW for this agent — its established work continues. CRITICAL
  // contains every unsafe action. Reads are never blocked by behaviour.
  const bh = input.behavior;
  if (bh === "unavailable") {
    warn("behavior.unavailable", "Could not assess this agent's behaviour.");
  } else if (bh && bh.level !== "NORMAL") {
    const key = destinationKey(destination);
    const novelAction = bh.established && !bh.knownActions.has(req.action);
    const novelDestination = bh.established && !!key && !bh.knownDestinations.has(key);
    // The anomaly's risk attaches to anomalous actions: the agent's
    // established work carries only a little extra, so it keeps flowing.
    const novel = novelAction || novelDestination;
    if (bh.level === "SUSPICIOUS") add(novel ? "new behaviour while suspicious" : "behaviour suspicious", novel ? 10 : 5);
    if (bh.level === "HIGH_RISK") {
      add(novel ? "new behaviour while high risk" : "behaviour high risk", novel ? 25 : 5);
      if (unsafe && (novelAction || novelDestination)) {
        hard("behavior.high_risk_novel_action",
          `This agent's behaviour is HIGH_RISK (score ${bh.score}); a ${novelAction ? "new kind of action" : "new destination"} that changes state or leaves Legion is held until a person reviews it.`);
      }
    }
    if (bh.level === "CRITICAL") {
      add("behaviour critical", 40);
      if (unsafe) {
        hard("behavior.critical_containment",
          `This agent's behaviour is CRITICAL (score ${bh.score}). Unsafe actions are contained until an administrator reviews it.`);
      }
    }
  }

  const pc = input.payloadClassification;
  if (req.surface === "agent_message" && pc) {
    if (pc.verdict === "malicious") {
      hard("a2a.injection_payload", `The message carries a prompt-injection payload (${pc.findingIds.join(", ")}); it would spread to the recipient.`);
    } else if (pc.verdict === "suspicious") {
      add("suspicious message payload", 15);
    }
  }

  // ---- Risk score -----------------------------------------------------------
  add(`agent risk ${p.riskLevel}`, { low: 0, medium: 10, high: 20, critical: 0 }[p.riskLevel]);
  if (permission) add(`permission tier ${PERMISSION_TIERS[permission]}`, PERMISSION_TIERS[permission] * 10);
  add(`sensitivity ${sensitivity}`, { public: 0, internal: 5, confidential: 20, restricted: 0 }[sensitivity]);
  if (externalEffect) add("effect outside Legion", 15);

  const v = policy.velocity;
  if (input.actionsLastMinute >= v.blockPerMinute) soft("velocity.block", `${input.actionsLastMinute} actions in the last minute (limit ${v.blockPerMinute}).`);
  else if (input.actionsLastMinute >= v.warnPerMinute) {
    warn("velocity.warn", `${input.actionsLastMinute} actions in the last minute.`);
    add("unusual action rate", 20);
  }

  return { hits, factors, permission, sensitivity, destination };
}

export function scoreOf(factors: RiskFactor[]): number {
  return Math.min(100, factors.reduce((s, f) => s + f.points, 0));
}
