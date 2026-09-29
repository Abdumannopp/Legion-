import { z } from "zod";
import { riskLevel, SEVERITIES, untrustedSummarySchema, type SkillDefinition } from "../types.js";
import { clip, isoMinusHours, levelOf, scoreEvent, type ScoredEvent } from "./common.js";

const input = z.strictObject({
  windowHours: z.number().int().min(1).max(168).default(24),
  minSeverity: z.enum(SEVERITIES).optional(),
  limit: z.number().int().min(1).max(500).default(200),
  eventIds: z.array(z.string().min(1).max(200)).min(1).max(500).optional(),
});

const finding = z.strictObject({
  eventId: z.string(),
  title: z.string(),
  time: z.string(),
  asset: z.string().nullable(),
  sourceIp: z.string().nullable(),
  riskLevel,
  score: z.number().int().min(0).max(100),
  patterns: z.array(z.string()),
  reasons: z.array(z.string()),
});

const group = z.strictObject({
  kind: z.enum(["source_ip", "asset", "technique"]),
  key: z.string(),
  eventIds: z.array(z.string()),
  count: z.number().int(),
  riskLevel,
  score: z.number().int().min(0).max(100),
  patterns: z.array(z.string()),
  reasons: z.array(z.string()),
});

const output = z.strictObject({
  window: z.strictObject({ from: z.string(), to: z.string() }),
  eventsAnalyzed: z.number().int(),
  findings: z.array(finding).max(200),
  groups: z.array(group).max(200),
  overallRisk: riskLevel,
  untrusted: untrustedSummarySchema,
  limitations: z.array(z.string()),
});

type Input = z.infer<typeof input>;
type Output = z.infer<typeof output>;

function groupBy(scored: ScoredEvent[], kind: "source_ip" | "asset" | "technique"): Output["groups"] {
  const buckets = new Map<string, ScoredEvent[]>();
  for (const s of scored) {
    const keys = kind === "source_ip" ? [s.event.sourceIp] : kind === "asset" ? [s.event.asset] : s.event.mitreTechniques;
    for (const k of keys) {
      if (!k) continue;
      const list = buckets.get(k) ?? [];
      list.push(s);
      buckets.set(k, list);
    }
  }
  const out: Output["groups"] = [];
  for (const [key, list] of buckets) {
    if (list.length < 2) continue;
    const sorted = [...list].sort((a, b) => a.event.createdAt.localeCompare(b.event.createdAt));
    const patterns = new Set<string>();
    const reasons = [`${list.length} related events share this ${kind.replace("_", " ")}.`];
    let score = Math.max(...list.map((s) => s.score)) + Math.min(20, 5 * (list.length - 1));
    const failures = sorted.filter((s) => s.reading.signals.some((x) => x.id === "failed_authentication"));
    if (failures.length >= 5) {
      patterns.add("brute_force");
      reasons.push(`${failures.length} failed authentications — consistent with brute force or password spraying.`);
      score += 20;
    }
    const firstFailure = failures[0]?.event.createdAt;
    const laterSuccess = firstFailure && sorted.find((s) => s.event.createdAt > firstFailure && s.reading.signals.some((x) => x.id === "successful_login"));
    if (failures.length >= 3 && laterSuccess) {
      patterns.add("success_after_failures");
      reasons.push(`A successful login (${laterSuccess.event.id}) followed the failures — the credential may have been guessed.`);
      score += 25;
    }
    const stages = new Set(list.flatMap((s) => s.reading.stages));
    if (stages.size >= 3) {
      patterns.add("multi_stage_activity");
      reasons.push(`Activity spans ${stages.size} attack stages (${[...stages].join(", ")}).`);
      score += 10;
    }
    if (list.some((s) => s.injection)) patterns.add("ai_manipulation_attempt");
    const capped = Math.min(100, score);
    out.push({
      kind, key: clip(key, 300), eventIds: sorted.map((s) => s.event.id).slice(0, 500), count: list.length,
      riskLevel: levelOf(capped), score: capped, patterns: [...patterns], reasons,
    });
  }
  return out.sort((a, b) => b.score - a.score);
}

export const threatDetection: SkillDefinition<Input, Output> = {
  name: "threat_detection",
  title: "Threat Detection",
  description: "Analyses the tenant's recent security events (Wazuh alerts), finds suspicious patterns, groups related events, assigns a risk level and explains why.",
  version: "1.0.0",
  input,
  output,
  capabilities: ["read:security_events"],
  auditEvents: ["skill.invoke"],
  example: { windowHours: 24, minSeverity: "medium" },
  limitations: [
    "Rule-based: it recognises the MITRE techniques and event wording listed in skills/knowledge.ts, not every attack.",
    "It only sees events Legion has ingested; gaps in sensor coverage are gaps here.",
  ],
  async handler(ctx, q) {
    const to = ctx.now.toISOString();
    const from = isoMinusHours(ctx.now, q.windowHours);
    const events = await ctx.data.securityEvents(
      q.eventIds ? { ids: q.eventIds, limit: q.eventIds.length } : { since: from, until: to, minSeverity: q.minSeverity, limit: q.limit },
    );
    const scored = events.map((e) => scoreEvent(ctx, e));
    const findings = scored
      .filter((s) => s.score >= 25 || s.patterns.length > 0)
      .sort((a, b) => b.score - a.score)
      .slice(0, 200)
      .map((s) => ({
        eventId: s.event.id, title: clip(s.event.title), time: s.event.createdAt, asset: s.event.asset ?? null, sourceIp: s.event.sourceIp ?? null,
        riskLevel: levelOf(s.score), score: s.score, patterns: s.patterns, reasons: s.reasons,
      }));
    const groups = [...groupBy(scored, "source_ip"), ...groupBy(scored, "asset"), ...groupBy(scored, "technique")].slice(0, 200);
    const top = Math.max(0, ...findings.map((f) => f.score), ...groups.map((g) => g.score));
    return {
      window: q.eventIds ? { from: events.map((e) => e.createdAt).sort()[0] ?? to, to } : { from, to },
      eventsAnalyzed: events.length,
      findings,
      groups,
      overallRisk: levelOf(top),
      untrusted: ctx.untrusted(),
      limitations: [...threatDetection.limitations],
    };
  },
};
