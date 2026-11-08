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

/** The response agent was called "Executor" until 2026-11. Old names still arrive from saved policies, queued work and older scripts. */
export const canonicalAgent = (name: unknown): unknown => (name === "Executor" ? "Vanguard" : name);

/** The same actor with a pre-rename agent name shown under the current one. The stored row is not changed (digests and the audit chain cover it). */
export function shownActor<T>(actor: T): T {
  const a = actor as { kind?: string; agent?: unknown } | null;
  return a && a.kind === "agent" && a.agent === "Executor" ? ({ ...a, agent: "Vanguard" } as T) : actor;
}

export const AGENTS = ["Sentinel", "Hunter", "Guardian", "Oracle", "Vanguard"] as const satisfies readonly Agent[];

/**
 * Where a request came from. `llm` means the action (or its parameters) were
 * produced by a language model: it never authorizes anything by itself.
 */
export const ORIGINS = ["human", "agent", "llm", "system"] as const;
export type Origin = (typeof ORIGINS)[number];

/**
 * shadow (observe only), simulation (compute, never apply) and live (really done). Live is possible only for
 * actions with an executor, only in a workspace whose administrator opted in (protection.ts), and never
 * for a critical action or an AI-produced one without a person's approval.
 */
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

/** What the workspace's protection settings say, as far as the policy decision needs it (protection.ts). */
export interface ProtectionView { mode: "manual" | "hybrid" | "automatic"; auto_actions: readonly string[] }
