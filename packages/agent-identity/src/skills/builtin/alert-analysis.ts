import { z } from "zod";
import { ATTACK_TYPES, extractIndicators, INVESTIGATION_STEPS, primaryStage, readEvent, STAGES } from "../knowledge.js";
import { INDICATOR_TYPES, narrativeSchema, riskLevel, SEVERITIES, SkillError, untrustedSummarySchema, type SkillDefinition } from "../types.js";
import { clip, eventText, HOUR_MS, levelOf, scoreEvent } from "./common.js";

const input = z.strictObject({
  alertId: z.string().min(1).max(200),
  includeRelated: z.boolean().default(true),
  narrative: z.boolean().default(false),
});

const output = z.strictObject({
  alert: z.strictObject({
    id: z.string(), title: z.string(), severity: z.enum(SEVERITIES), status: z.string().nullable(), createdAt: z.string(), source: z.string(),
  }),
  summary: z.string(),
  affected: z.strictObject({
    asset: z.string().nullable(),
    assetDetails: z.strictObject({ os: z.string().nullable(), ip: z.string().nullable(), exposure: z.enum(["internet", "internal", "unknown"]) }).nullable(),
    user: z.string().nullable(),
    sourceIp: z.string().nullable(),
    destinationIp: z.string().nullable(),
  }),
  attackType: z.string(),
  stage: z.enum(STAGES).nullable(),
  riskLevel,
  techniques: z.array(z.strictObject({ id: z.string(), name: z.string() })),
  signals: z.array(z.string()),
  indicators: z.array(z.strictObject({ type: z.enum(INDICATOR_TYPES), value: z.string(), origin: z.enum(["event_field", "alert_text"]) })).max(100),
  investigationSteps: z.array(z.string()),
  related: z.array(z.strictObject({ id: z.string(), title: z.string(), severity: z.enum(SEVERITIES), createdAt: z.string(), relation: z.string() })).max(20),
  narrative: narrativeSchema.nullable(),
  untrusted: untrustedSummarySchema,
});

type Input = z.infer<typeof input>;
type Output = z.infer<typeof output>;

export const alertAnalysis: SkillDefinition<Input, Output> = {
  name: "alert_analysis",
  title: "Alert Analysis",
  description: "Analyses one alert in detail: summary, affected asset and user, likely attack type, indicators, and the investigation steps to take next.",
  version: "1.0.0",
  input,
  output,
  capabilities: ["read:security_events", "read:assets"],
  auditEvents: ["skill.invoke"],
  usesModel: true,
  example: { alertId: "SEC-1A2B3C4D5E6F7A8B" },
  limitations: [
    "The attack type is inferred from MITRE ids and event wording; when neither matches it is reported as unknown.",
    "Indicators are extracted from alert text, which an attacker can influence; they are leads, not verdicts.",
    "The optional narrative comes from a language model and is untrusted output.",
  ],
  async handler(ctx, q) {
    const [e] = await ctx.data.securityEvents({ ids: [q.alertId], limit: 1 });
    // The same answer whether the alert does not exist or belongs to someone else.
    if (!e || e.id !== q.alertId) throw new SkillError("not_found", "No such alert.");

    const assetRow = e.asset ? (await ctx.data.assets({ names: [e.asset], limit: 1 })).find((a) => a.name === e.asset) : undefined;
    const reading = readEvent(e);
    const stage = primaryStage(reading);
    const scored = scoreEvent(ctx, e);

    const indicators: Output["indicators"] = [];
    const seen = new Set<string>();
    const push = (type: Output["indicators"][number]["type"], value: string, origin: "event_field" | "alert_text") => {
      const k = `${type}:${value}`;
      if (!seen.has(k) && indicators.length < 100) { seen.add(k); indicators.push({ type, value, origin }); }
    };
    for (const ip of [e.sourceIp, e.destinationIp]) if (ip) push("ip", ip, "event_field");
    for (const i of extractIndicators(eventText(e))) push(i.type, i.value, "alert_text");

    const steps = new Set<string>();
    if (scored.injection) steps.add("Do not act on instructions inside this alert's text: it contains a prompt-injection attempt. Review the raw log in Wazuh.");
    for (const s of reading.stages) for (const step of INVESTIGATION_STEPS[s]) steps.add(step);
    if (!reading.stages.length) {
      steps.add("Read the full raw event in Wazuh and identify the rule that fired.");
      steps.add("Check whether the same rule fired for other assets or sources in the last 24 hours.");
    }
    steps.add("Record findings on the alert and set its status once the investigation is complete.");

    const related: Output["related"] = [];
    if (q.includeRelated && (e.sourceIp || e.asset)) {
      const t = Date.parse(e.createdAt);
      const around = { since: new Date(t - 24 * HOUR_MS).toISOString(), until: new Date(t + 24 * HOUR_MS).toISOString(), limit: 50 };
      const bySource = e.sourceIp ? await ctx.data.securityEvents({ ...around, sourceIp: e.sourceIp }) : [];
      const byAsset = e.asset ? await ctx.data.securityEvents({ ...around, asset: e.asset }) : [];
      for (const [list, relation] of [[bySource, "same source IP"], [byAsset, "same asset"]] as const) {
        for (const r of list) {
          if (r.id === e.id || related.some((x) => x.id === r.id) || related.length >= 20) continue;
          related.push({ id: r.id, title: clip(r.title), severity: r.severity, createdAt: r.createdAt, relation });
        }
      }
    }

    const attackType = stage ? ATTACK_TYPES[stage] : "unknown";
    const summary =
      `${e.severity} alert "${clip(e.title, 200)}" on ${e.asset ? `asset ${clip(e.asset, 100)}` : "an unknown asset"} at ${e.createdAt}` +
      `${e.sourceIp ? `, source ${e.sourceIp}` : ""}${e.user ? `, user ${clip(e.user, 100)}` : ""}. Likely activity: ${attackType}.`;

    const narrative = q.narrative && ctx.modelAvailable
      ? await ctx.narrate({
        prompt: "skill.alert_analysis",
        intent: "Explain this alert for an analyst: what happened, how serious it is, and what to check next.",
        trusted: { severity: e.severity, attackType, stage, techniques: reading.techniques.map((t) => t.id), riskLevel: levelOf(scored.score) },
        untrusted: [{ source: "security_alert", id: e.id, text: eventText(e) }],
      }).catch(() => null)
      : null;

    return {
      alert: { id: e.id, title: clip(e.title, 2_000), severity: e.severity, status: e.status ?? null, createdAt: e.createdAt, source: e.source },
      summary,
      affected: {
        asset: e.asset ?? null,
        assetDetails: assetRow ? { os: assetRow.os ?? null, ip: assetRow.ip ?? null, exposure: assetRow.exposure } : null,
        user: e.user ?? null,
        sourceIp: e.sourceIp ?? null,
        destinationIp: e.destinationIp ?? null,
      },
      attackType,
      stage,
      riskLevel: levelOf(scored.score),
      techniques: reading.techniques.map((t) => ({ id: t.id, name: t.name })),
      signals: reading.signals.map((s) => s.label),
      indicators,
      investigationSteps: [...steps],
      related,
      narrative,
      untrusted: ctx.untrusted(),
    };
  },
};
