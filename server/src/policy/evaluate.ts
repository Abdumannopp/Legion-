/**
 * The policy decision. Pure and deterministic: no I/O, no clock, no model.
 * Same request + same policy → same decision, always.
 *
 * Order:
 *   1. Hard refusals: unknown action, unknown or unauthorised agent, live mode without an executor or
 *      without the workspace's opt-in (protection.ts).
 *   2. Base decision from autonomy (action > agent > workspace default).
 *   3. Matching rules: if any match, the strictest of them replaces the base.
 *      (An ALLOW rule may grant autonomy; a DENY can never be overridden.)
 *   4. Floors no policy can lower: R4 always needs approval; R3 by a
 *      non-human needs approval; anything a model produced above R0 needs
 *      approval; R0 reads are allowed unless a rule denies them.
 */
import type { Agent } from "../types.js";
import { CATALOG_VERSION, LIVE_ACTION_IDS, catalogEntry } from "./catalog.js";
import { DEFAULT_POLICY, type PolicyDocument, type PolicyRule } from "./document.js";
import { explain } from "./explain.js";
import { AGENTS, canonicalAgent, type ActorRef, type Autonomy, type Decision, type ExecutionMode, type Origin, type ProtectionView, type RiskClass, riskRank, strictest } from "./types.js";

export const ENGINE_VERSION = "policy-v0.1";

export interface PolicyRequest {
  action_id: string;
  actor: ActorRef;
  origin: Origin;
  mode: ExecutionMode;
  /** The workspace's protection settings; only read in live mode. Absent = manual = no live execution. */
  protection?: ProtectionView;
}

export interface PolicyOutcome {
  decision: Decision;
  action_id: string;
  risk_class: RiskClass | null;
  autonomy: Autonomy | null;
  matched_rule_ids: string[];
  reason_codes: string[];
  explanation: string;
  catalog_version: string;
  engine_version: string;
}

export type ReasonCode =
  | "UNKNOWN_ACTION" | "UNKNOWN_AGENT" | "AGENT_NOT_ALLOWED" | "LIVE_MODE_DISABLED" | "NO_LIVE_EXECUTOR" | "LIVE_NOT_ENABLED"
  | "PROTECTION_AUTHORIZED" | "PROTECTION_ASK" | "LIVE_RATE_LIMIT" | "ACTOR_ORIGIN_MISMATCH"
  | "READ_ONLY" | "AUTONOMY_OBSERVE" | "AUTONOMY_ASSIST" | "AUTONOMY_AUTONOMOUS" | "AUTONOMY_LIMIT_R3"
  | "HUMAN_DIRECT" | "RULE_MATCHED"
  | "FLOOR_CRITICAL" | "FLOOR_R3_NON_HUMAN" | "FLOOR_LLM_ORIGIN";

function outcome(req: PolicyRequest, decision: Decision, codes: ReasonCode[], extra: Partial<PolicyOutcome> = {}): PolicyOutcome {
  return {
    decision, action_id: req.action_id, risk_class: null, autonomy: null, matched_rule_ids: [],
    reason_codes: codes, explanation: explain(decision, codes, extra.matched_rule_ids ?? []),
    catalog_version: CATALOG_VERSION, engine_version: ENGINE_VERSION, ...extra,
  };
}

function ruleMatches(rule: PolicyRule, actionId: string, cls: RiskClass, agent: Agent | null, origin: Origin): boolean {
  if (!rule.actions.includes("*") && !rule.actions.includes(actionId)) return false;
  if (rule.agents && (!agent || !rule.agents.includes(agent))) return false;
  if (rule.origins && !rule.origins.includes(origin)) return false;
  if (rule.classes && !rule.classes.includes(cls)) return false;
  return true;
}

export function evaluatePolicy(req: PolicyRequest, policy: PolicyDocument | null): PolicyOutcome {
  const doc = policy ?? DEFAULT_POLICY;
  const entry = catalogEntry(req.action_id);
  if (!entry) return outcome(req, "DENY", ["UNKNOWN_ACTION"]);
  const cls = entry.class;
  const base = { risk_class: cls };

  // A human origin must come with a human actor, and a human actor cannot
  // carry an agent/llm origin: the caller states both, the engine checks them.
  if ((req.origin === "human") !== (req.actor.kind === "human")) return outcome(req, "DENY", ["ACTOR_ORIGIN_MISMATCH"], base);

  let agent: Agent | null = null;
  if (req.actor.kind === "agent") {
    // Work queued before the rename may still name the agent "Executor": it is the same agent.
    const named = canonicalAgent(req.actor.agent) as string;
    if (!(AGENTS as readonly string[]).includes(named)) return outcome(req, "DENY", ["UNKNOWN_AGENT"], base);
    agent = named as Agent;
    if (!entry.agents.includes(agent)) return outcome(req, "DENY", ["AGENT_NOT_ALLOWED"], base);
  }
  // Live: only what Legion can really do, and only where an administrator opted in. A policy document
  // cannot grant either; it can still refuse or require approval below.
  const live = req.mode === "live";
  if (live) {
    if (!LIVE_ACTION_IDS.includes(req.action_id)) return outcome(req, "DENY", ["NO_LIVE_EXECUTOR"], base);
    if (!req.protection || req.protection.mode === "manual") return outcome(req, "DENY", ["LIVE_NOT_ENABLED"], base);
  }
  // Pre-authorised by the administrator: hybrid = the chosen list; automatic = everything with an executor
  // that is not critical. R4 is never authorised here (the floor below also holds).
  const preauthorized = live && !!req.protection && cls !== "R4" && (
    req.protection.mode === "automatic" || (req.protection.mode === "hybrid" && req.protection.auto_actions.includes(req.action_id)));

  const codes: ReasonCode[] = [];
  const autonomy: Autonomy = doc.actions?.[req.action_id]?.autonomy ?? (agent ? doc.agents?.[agent]?.autonomy : undefined) ?? doc.default_autonomy;

  // 2. Base decision.
  let decision: Decision;
  if (cls === "R0") { decision = "ALLOW"; codes.push("READ_ONLY"); }
  else if (req.actor.kind === "human") { decision = "ALLOW"; codes.push("HUMAN_DIRECT"); }
  // Live, by a machine: the workspace's own choice decides, not the (default: observe-only) policy autonomy.
  else if (live) { decision = preauthorized ? "ALLOW" : "REQUIRE_APPROVAL"; codes.push(preauthorized ? "PROTECTION_AUTHORIZED" : "PROTECTION_ASK"); }
  else if (autonomy === "OBSERVE") { decision = "RECORD_ONLY"; codes.push("AUTONOMY_OBSERVE"); }
  else if (autonomy === "ASSIST") { decision = "REQUIRE_APPROVAL"; codes.push("AUTONOMY_ASSIST"); }
  else if (riskRank(cls) >= riskRank("R3")) { decision = "REQUIRE_APPROVAL"; codes.push("AUTONOMY_LIMIT_R3"); }
  else { decision = "ALLOW"; codes.push("AUTONOMY_AUTONOMOUS"); }

  // 3. Rules: the strictest matching rule replaces the base.
  const matched = doc.rules.filter((r) => ruleMatches(r, req.action_id, cls, agent, req.origin));
  if (matched.length) {
    const byRules = matched.map((r) => r.effect as Decision).reduce(strictest);
    // Live: what may run on its own is the administrator's protection setting, not a rule. A rule can
    // refuse, record only or require approval; it cannot grant.
    decision = live ? strictest(decision, byRules) : byRules;
    codes.push("RULE_MATCHED");
  }

  // 4. Floors. They only ever make the decision stricter.
  if (cls === "R4" && decision === "ALLOW") { decision = "REQUIRE_APPROVAL"; codes.push("FLOOR_CRITICAL"); }
  // The administrator's written pre-authorisation is what lifts this floor for a live action; nothing else does.
  if (cls === "R3" && req.actor.kind !== "human" && decision === "ALLOW" && !preauthorized) { decision = "REQUIRE_APPROVAL"; codes.push("FLOOR_R3_NON_HUMAN"); }
  if (req.origin === "llm" && cls !== "R0" && decision === "ALLOW") { decision = "REQUIRE_APPROVAL"; codes.push("FLOOR_LLM_ORIGIN"); }
  // R4 and R3-by-machine with RECORD_ONLY stay RECORD_ONLY (stricter than asking).

  return outcome(req, decision, codes, { ...base, autonomy, matched_rule_ids: matched.map((r) => r.id) });
}
