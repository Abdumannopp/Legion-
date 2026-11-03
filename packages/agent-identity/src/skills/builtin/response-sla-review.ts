import { z } from "zod";
import { riskLevel, untrustedSummarySchema, type SecurityEvent, type SkillDefinition } from "../types.js";
import { clip, HOUR_MS, isoMinusHours } from "./common.js";

/*
 * Oracle: are alerts being answered in time. A business that sells to other
 * businesses is asked "how fast do you respond to a security alert?". This
 * answers it with the workspace's own numbers: every open alert measured
 * against a target for its severity, and the ones that are late.
 */

export const DEFAULT_TARGET_HOURS = { critical: 4, high: 24, medium: 72, low: 168 } as const;
type Sev = keyof typeof DEFAULT_TARGET_HOURS;
const SEVS: readonly Sev[] = ["critical", "high", "medium", "low"];

const input = z.strictObject({
  criticalHours: z.number().int().min(1).max(720).default(DEFAULT_TARGET_HOURS.critical),
  highHours: z.number().int().min(1).max(720).default(DEFAULT_TARGET_HOURS.high),
  mediumHours: z.number().int().min(1).max(720).default(DEFAULT_TARGET_HOURS.medium),
  lowHours: z.number().int().min(1).max(720).default(DEFAULT_TARGET_HOURS.low),
  windowDays: z.number().int().min(1).max(90).default(30),
  limit: z.number().int().min(1).max(50).default(20),
});

const sevCounts = z.strictObject({ critical: z.number().int(), high: z.number().int(), medium: z.number().int(), low: z.number().int() });

const output = z.strictObject({
  window: z.strictObject({ from: z.string(), to: z.string() }),
  targetsHours: sevCounts,
  summary: z.strictObject({
    open: sevCounts,
    overdue: sevCounts,
    onTimePercent: z.number().int().min(0).max(100).nullable(),
    oldestOpenHours: z.number().nullable(),
    text: z.string(),
  }),
  overdue: z.array(z.strictObject({
    eventId: z.string(),
    title: z.string(),
    severity: z.enum(["critical", "high", "medium", "low"]),
    asset: z.string().nullable(),
    openHours: z.number(),
    lateByHours: z.number(),
    riskLevel,
  })).max(50),
  byAsset: z.array(z.strictObject({ asset: z.string(), overdue: z.number().int() })).max(20),
  untrusted: untrustedSummarySchema,
  limitations: z.array(z.string()),
});

type Input = z.infer<typeof input>;
type Output = z.infer<typeof output>;

const zero = (): Record<Sev, number> => ({ critical: 0, high: 0, medium: 0, low: 0 });

export const responseSlaReview: SkillDefinition<Input, Output> = {
  name: "response_sla_review",
  agent: "Oracle",
  title: "Response Time Review",
  description: "Measures every open alert against a response target for its severity (default: critical 4 h, high 24 h, medium 3 days, low 7 days) and lists the ones that are late, with how late and on which asset. Gives the share of open alerts that are on time.",
  version: "1.0.0",
  input,
  output,
  capabilities: ["read:security_events"],
  auditEvents: ["skill.invoke"],
  example: { windowDays: 30, limit: 20 },
  limitations: [
    "Legion does not record when an alert was resolved, so it cannot say how long closed alerts took. It measures only what is still open: how long it has waited.",
    "It reads at most the 500 newest high and critical alerts and the 500 newest of any severity in the window. On a very busy workspace an older open alert can be outside them.",
    "The targets are yours to choose; the defaults are common starting points, not a legal or contractual standard.",
    "'Open' means not marked resolved. An alert someone is working on (investigating) still counts as open.",
    "It does not assign, close or escalate anything.",
  ],
  async handler(ctx, q) {
    const targets: Record<Sev, number> = { critical: q.criticalHours, high: q.highHours, medium: q.mediumHours, low: q.lowHours };
    const to = ctx.now.toISOString();
    const from = isoMinusHours(ctx.now, q.windowDays * 24);
    // Two reads: the serious ones deeply (a busy workspace's noise must not push an old critical out), then everything recent.
    const [serious, recent] = await Promise.all([
      ctx.data.securityEvents({ since: from, until: to, minSeverity: "high", limit: 500 }),
      ctx.data.securityEvents({ since: from, until: to, limit: 500 }),
    ]);
    const byId = new Map<string, SecurityEvent>();
    for (const e of [...serious, ...recent]) byId.set(e.id, e);
    const open = [...byId.values()].filter((e) => (e.status ?? "open") !== "resolved");

    const openCount = zero();
    const overdueCount = zero();
    const late: Output["overdue"] = [];
    let oldest: number | null = null;
    for (const e of open) {
      const sev = e.severity as Sev;
      const hours = Math.max(0, (ctx.now.getTime() - new Date(e.createdAt).getTime()) / HOUR_MS);
      openCount[sev]++;
      oldest = oldest === null ? hours : Math.max(oldest, hours);
      const lateBy = hours - targets[sev];
      if (lateBy > 0) {
        overdueCount[sev]++;
        late.push({
          eventId: e.id, title: clip(e.title), severity: sev, asset: e.asset ? clip(e.asset, 200) : null,
          openHours: Math.round(hours * 10) / 10, lateByHours: Math.round(lateBy * 10) / 10,
          riskLevel: sev === "critical" ? "critical" : sev === "high" ? "high" : "medium",
        });
      }
    }
    const rank = { critical: 4, high: 3, medium: 2, low: 1 } as const;
    late.sort((a, b) => rank[b.severity] - rank[a.severity] || b.lateByHours - a.lateByHours);

    const totalOpen = SEVS.reduce((n, s) => n + openCount[s], 0);
    const totalLate = SEVS.reduce((n, s) => n + overdueCount[s], 0);
    const onTime = totalOpen ? Math.round(((totalOpen - totalLate) / totalOpen) * 100) : null;
    const byAssetMap = new Map<string, number>();
    for (const l of late) if (l.asset) byAssetMap.set(l.asset, (byAssetMap.get(l.asset) ?? 0) + 1);

    const text = !totalOpen ? "No open alerts in this window."
      : !totalLate ? `All ${totalOpen} open alerts are within their response targets.`
      : `${totalLate} of ${totalOpen} open alerts are late${overdueCount.critical ? `, including ${overdueCount.critical} critical` : ""}. The oldest has waited ${Math.round(oldest ?? 0)} hours.`;

    return {
      window: { from, to },
      targetsHours: targets,
      summary: { open: openCount, overdue: overdueCount, onTimePercent: onTime, oldestOpenHours: oldest === null ? null : Math.round(oldest * 10) / 10, text },
      overdue: late.slice(0, q.limit),
      byAsset: [...byAssetMap].map(([asset, overdue]) => ({ asset, overdue })).sort((a, b) => b.overdue - a.overdue).slice(0, 20),
      untrusted: ctx.untrusted(),
      limitations: [...responseSlaReview.limitations],
    };
  },
};
