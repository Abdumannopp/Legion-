import { isPermission, PERMISSION_TIERS } from "../../permissions.js";
import { PromptAssembly, reviewProposedAction } from "../../prompt-guard/assembly.js";
import { levelOf, readEvent, SEVERITY_POINTS, type EventReading } from "../knowledge.js";
import type { ProposedActionOut, SecurityEvent, SkillContext } from "../types.js";

export const HOUR_MS = 3_600_000;

export function isoMinusHours(now: Date, hours: number): string {
  return new Date(now.getTime() - hours * HOUR_MS).toISOString();
}

/** Short, single-line rendering of untrusted text for summaries. */
export function clip(text: string | null | undefined, max = 300): string {
  const t = (text ?? "").replace(/\s+/g, " ").trim();
  return t.length > max ? `${t.slice(0, max)}…` : t;
}

export function eventText(e: SecurityEvent): string {
  return [e.title, e.summary, e.process, e.filePath].filter(Boolean).join("\n");
}

export interface ScoredEvent {
  event: SecurityEvent;
  reading: EventReading;
  score: number;
  reasons: string[];
  patterns: string[];
  injection: boolean;
}

/** Risk of one event, with every point explained. */
export function scoreEvent(ctx: SkillContext, e: SecurityEvent): ScoredEvent {
  const reading = readEvent(e);
  const reasons = [`Sensor severity ${e.severity}.`];
  let score: number = SEVERITY_POINTS[e.severity];
  for (const t of reading.techniques) {
    score += t.points;
    reasons.push(`MITRE ${t.id} (${t.name}).`);
  }
  for (const s of reading.signals) {
    score += s.points;
    reasons.push(`${s.label} described in the event.`);
  }
  const patterns = [...reading.signals.map((s) => s.id), ...reading.techniques.map((t) => `mitre:${t.id}`)];
  const injection = ctx.verdictOf(e.id) !== "clean";
  if (injection) {
    score += 15;
    patterns.push("ai_manipulation_attempt");
    reasons.push("The event text contains instructions aimed at an AI reader (prompt injection). It was treated as data, not followed; the attempt itself is suspicious.");
  }
  return { event: e, reading, score: Math.min(100, score), reasons, patterns, injection };
}

export { levelOf };

/**
 * A recommendation, never an action. Actions Legion can let a machine do go
 * through reviewProposedAction() against the external content the plan was
 * built from; actions only a person can take are marked humanOnly and
 * always need confirmation.
 */
export function propose(
  assembly: PromptAssembly,
  p: { action: string; description: string; permission: string | null; humanOnly: boolean; destructive: boolean; external?: boolean },
): ProposedActionOut {
  const permission = p.permission && isPermission(p.permission) ? p.permission : null;
  if (p.humanOnly || !permission) {
    const reasons = ["Only a person can take this action; Legion gives agents no permission for it."];
    if (assembly.verdict === "malicious") reasons.push("The plan was built from content flagged as malicious: verify the evidence independently first.");
    else if (assembly.tainted) reasons.push("The plan was built from external content: verify the evidence first.");
    return { ...p, permission: p.permission, humanOnly: true, review: "confirm", reviewReasons: reasons, executed: false };
  }
  const r = reviewProposedAction(assembly, { action: p.action, permission, external: p.external });
  const reasons = [...r.reasons];
  if (PERMISSION_TIERS[permission] >= 2) reasons.push(`Needs ${permission}, checked again by the agent firewall when it is actually requested.`);
  return { ...p, permission, humanOnly: false, review: r.decision, reviewReasons: reasons.slice(0, 10), executed: false };
}

/** The external content a plan is based on, as a prompt assembly (classification only; nothing is sent anywhere). */
export function assemblyOf(events: SecurityEvent[]): PromptAssembly {
  const a = new PromptAssembly("skill.incident_response");
  for (const e of events) a.addUntrustedContent("security_alert", eventText(e), { sourceId: e.id });
  return a;
}

/** Escapes Markdown and defangs links so untrusted text in a report cannot become a link, image or heading. */
export function mdSafe(text: string | null | undefined): string {
  return (text ?? "")
    .replace(/\bhttps?:\/\//gi, (m) => m.replace(/^h/i, "hxx").replace(/tt/i, ""))
    .replace(/[\\`*_{}[\]()#+!|<>~]/g, "\\$&")
    .replace(/\r?\n/g, " ");
}
