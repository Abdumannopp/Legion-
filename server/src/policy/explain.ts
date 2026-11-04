/** Plain-English explanation of a decision, built only from fixed templates. */
import type { Decision } from "./types.js";

const TEXT: Record<string, string> = {
  UNKNOWN_ACTION: "Legion does not know this action, so it is refused.",
  UNKNOWN_AGENT: "This agent is not one of Legion's agents, so it is refused.",
  AGENT_NOT_ALLOWED: "This agent may not propose this kind of action.",
  ACTOR_ORIGIN_MISMATCH: "Who is acting does not match where the request came from, so it is refused.",
  LIVE_MODE_DISABLED: "Live execution is not available yet; only shadow and simulation run.",
  READ_ONLY: "The action only reads data.",
  HUMAN_DIRECT: "A signed-in person is acting directly; their role was checked separately.",
  AUTONOMY_OBSERVE: "Agents only observe in this workspace: the action is recorded, not done.",
  AUTONOMY_ASSIST: "Agents assist in this workspace: a person must approve the action.",
  AUTONOMY_AUTONOMOUS: "Agents may act on their own for this kind of action.",
  AUTONOMY_LIMIT_R3: "Even autonomous agents need approval for high-risk actions.",
  RULE_MATCHED: "A workspace policy rule applies.",
  FLOOR_CRITICAL: "Critical actions always need a person's approval.",
  FLOOR_R3_NON_HUMAN: "High-risk actions proposed by an agent always need a person's approval.",
  FLOOR_LLM_ORIGIN: "The action was proposed by an AI model, so a person must approve it.",
};

const VERDICT: Record<Decision, string> = {
  ALLOW: "Allowed.",
  REQUIRE_APPROVAL: "Needs a person's approval.",
  RECORD_ONLY: "Recorded only; nothing is done.",
  DENY: "Refused.",
};

export function explain(decision: Decision, codes: readonly string[], ruleIds: readonly string[]): string {
  const parts = [VERDICT[decision], ...codes.map((c) => TEXT[c] ?? c)];
  if (ruleIds.length) parts.push(`Rules: ${ruleIds.join(", ")}.`);
  return parts.join(" ").slice(0, 2000);
}
