import { z } from "zod";
import { INVESTIGATION_STEPS, primaryStage } from "../knowledge.js";
import { riskLevel, untrustedSummarySchema, type SkillDefinition } from "../types.js";
import { clip, isoMinusHours, levelOf, scoreEvent } from "./common.js";

/*
 * Oracle: with forty open alerts and five minutes, which one first, and why.
 * It orders the queue; it does not close anything. Every point in a score is
 * explained so a person can disagree with it.
 */

const NOW_AT = 70;
const TODAY_AT = 45;

const input = z.strictObject({
  windowHours: z.number().int().min(1).max(168).default(24),
  limit: z.number().int().min(1).max(50).default(20),
});

const priority = z.enum(["now", "today", "this_week"]);

const output = z.strictObject({
  window: z.strictObject({ from: z.string(), to: z.string() }),
  queue: z.array(z.strictObject({
    rank: z.number().int(),
    eventId: z.string(),
    title: z.string(),
    asset: z.string().nullable(),
    priority,
    riskLevel,
    score: z.number().int().min(0).max(100),
    why: z.array(z.string()).max(12),
    firstStep: z.string(),
  })).max(50),
  summary: z.strictObject({
    open: z.number().int(),
    now: z.number().int(),
    today: z.number().int(),
    thisWeek: z.number().int(),
    text: z.string(),
  }),
  untrusted: untrustedSummarySchema,
  limitations: z.array(z.string()),
});

type Input = z.infer<typeof input>;
type Output = z.infer<typeof output>;

export const triagePriority: SkillDefinition<Input, Output> = {
  name: "triage_priority",
  agent: "Oracle",
  title: "Triage Priority",
  description: "Puts the open alerts in the order a person should handle them. Each alert's score adds up its severity, the attack technique, whether the asset is reachable from the internet, and whether the same address or host is behind several alerts, and says why. Resolved alerts are left out.",
  version: "1.0.0",
  input,
  output,
  capabilities: ["read:security_events", "read:assets"],
  auditEvents: ["skill.invoke"],
  example: { windowHours: 24, limit: 20 },
  limitations: [
    "It ranks by the evidence in the alerts. It does not know which asset matters most to your business; a high score on a test server can still outrank a medium one on the payment system.",
    "It does not close, assign or change any alert.",
    "Alert text can be written by an attacker. An alert that tries to steer the ranking is scored higher, not followed.",
  ],
  async handler(ctx, q) {
    const to = ctx.now.toISOString();
    const from = isoMinusHours(ctx.now, q.windowHours);
    const [events, assets] = await Promise.all([
      ctx.data.securityEvents({ since: from, until: to, limit: 500 }),
      ctx.data.assets({ limit: 200 }),
    ]);
    const open = events.filter((e) => (e.status ?? "open") !== "resolved");
    const exposure = new Map(assets.map((a) => [a.name.toLowerCase(), a.exposure]));

    const perIp = new Map<string, number>();
    const perAsset = new Map<string, number>();
    for (const e of open) {
      if (e.sourceIp) perIp.set(e.sourceIp, (perIp.get(e.sourceIp) ?? 0) + 1);
      if (e.asset) perAsset.set(e.asset.toLowerCase(), (perAsset.get(e.asset.toLowerCase()) ?? 0) + 1);
    }

    const ranked = open.map((e) => {
      const s = scoreEvent(ctx, e);
      let score = s.score;
      const why = [...s.reasons];
      if (e.asset && exposure.get(e.asset.toLowerCase()) === "internet") { score += 10; why.push(`${clip(e.asset, 100)} is reachable from the internet.`); }
      const sameIp = e.sourceIp ? perIp.get(e.sourceIp) ?? 0 : 0;
      if (sameIp >= 3) { score += 10; why.push(`${sameIp} open alerts come from the same address.`); }
      const sameAsset = e.asset ? perAsset.get(e.asset.toLowerCase()) ?? 0 : 0;
      if (sameAsset >= 3) { score += 5; why.push(`${sameAsset} open alerts concern the same asset.`); }
      if (ctx.now.getTime() - new Date(e.createdAt).getTime() <= 3_600_000) { score += 5; why.push("Happened in the last hour."); }
      score = Math.min(100, score);
      const stage = primaryStage(s.reading);
      return { e, score, why, firstStep: (stage && INVESTIGATION_STEPS[stage]?.[0]) || "Read the alert, then confirm with the owner whether the activity was expected." };
    }).sort((a, b) => b.score - a.score || b.e.createdAt.localeCompare(a.e.createdAt));

    const tier = (score: number): z.infer<typeof priority> => (score >= NOW_AT ? "now" : score >= TODAY_AT ? "today" : "this_week");
    const count = { now: 0, today: 0, this_week: 0 };
    for (const r of ranked) count[tier(r.score)]++;

    const text = !ranked.length
      ? "No open alerts in this window."
      : count.now
        ? `${count.now} of ${ranked.length} open alerts need attention now. Start with the first one in the queue.`
        : count.today
          ? `Nothing is urgent right now; ${count.today} of ${ranked.length} open alerts should be handled today.`
          : `${ranked.length} open alerts, none urgent. Review them this week.`;

    return {
      window: { from, to },
      queue: ranked.slice(0, q.limit).map((r, i) => ({
        rank: i + 1, eventId: r.e.id, title: clip(r.e.title), asset: r.e.asset ? clip(r.e.asset, 200) : null,
        priority: tier(r.score), riskLevel: levelOf(r.score), score: r.score, why: r.why.slice(0, 12), firstStep: r.firstStep,
      })),
      summary: { open: ranked.length, now: count.now, today: count.today, thisWeek: count.this_week, text },
      untrusted: ctx.untrusted(),
      limitations: [...triagePriority.limitations],
    };
  },
};
