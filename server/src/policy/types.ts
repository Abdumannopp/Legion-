/**
 * Shared vocabulary of the SOC core (Task 10): who acts, how risky an action
 * is, what the policy engine decides, and in which mode anything runs.
 */
import type { Agent, Role } from "../types.js";

/** R0 read-only … R4 critical (destructive, financial, or hard to reverse). */
export const RISK_CLASSES = ["R0", "R1", "R2", "R3", "R4"] as const;
export type RiskClass = (typeof RISK_CLASSES)[number];
export const riskRank = (c: RiskClass): number => RISK_CLASSES.indexOf(c);

/** Ordered least → most restrictive. A stricter decision always wins. */
export const DECISIONS = ["ALLOW", "REQUIRE_APPROVAL", "RECORD_ONLY", "DENY"] as const;
export type Decision = (typeof DECISIONS)[number];
export const strictest = (a: Decision, b: Decision): Decision => (DECISIONS.indexOf(a) >= DECISIONS.indexOf(b) ? a : b);

export const AUTONOMY = ["OBSERVE", "ASSIST", "AUTONOMOUS"] as const;
export type Autonomy = (typeof AUTONOMY)[number];

export const AGENTS = ["Sentinel", "Hunter", "Guardian", "Oracle", "Vanguard"] as const satisfies readonly Agent[];

/**
 * Where a request came from. `llm` means the action (or its parameters) were
 * produced by a language model: it never authorizes anything by itself.
 */
export const ORIGINS = ["human", "agent", "llm", "system"] as const;
export type Origin = (typeof ORIGINS)[number];

/** v0 runs nothing live: shadow (observe only) and simulation (compute, never apply). */
export const EXECUTION_MODES = ["shadow", "simulation", "live"] as const;
export type ExecutionMode = (typeof EXECUTION_MODES)[number];

/**
 * Who is acting. Always built by server code from a verified session or from
 * the engine that runs an agent — never parsed from model output or request
 * bodies.
 */
export type ActorRef =
  | { kind: "human"; user_id: string; role: Role }
  | { kind: "agent"; agent: Agent }
  | { kind: "system"; component: string };
