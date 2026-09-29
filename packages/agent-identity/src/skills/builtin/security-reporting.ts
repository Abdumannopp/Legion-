import { z } from "zod";
import { classifyContent } from "../../prompt-guard/detectors.js";
import { ATTACK_TYPES, INVESTIGATION_STEPS, readEvent, STAGES } from "../knowledge.js";
import { narrativeSchema, riskLevel, SEVERITIES, SkillError, untrustedSummarySchema, type SkillDefinition } from "../types.js";
import { clip, eventText, levelOf, mdSafe, scoreEvent } from "./common.js";

const input = z.strictObject({
  alertIds: z.array(z.string().min(1).max(200)).min(1).max(100),
  title: z.string().min(1).max(200).optional(),
  /** What the requester says was already done. Reported as their claim, not verified. */
  actionsTaken: z.array(z.string().min(1).max(500)).max(20).default([]),
  audience: z.enum(["technical", "executive"]).default("technical"),
  narrative: z.boolean().default(false),
});

const output = z.strictObject({
  report: z.strictObject({
    title: z.string(),
    generatedAt: z.string(),
    audience: z.enum(["technical", "executive"]),
    whatHappened: z.string(),
    when: z.strictObject({ first: z.string(), last: z.string() }),
    affectedAssets: z.array(z.strictObject({ name: z.string(), exposure: z.enum(["internet", "internal", "unknown"]) })),
    risk: z.strictObject({ level: riskLevel, score: z.number().int(), reasons: z.array(z.string()) }),
    evidence: z.array(z.strictObject({
      eventId: z.string(), time: z.string(), title: z.string(), severity: z.enum(SEVERITIES), asset: z.string().nullable(), sourceIp: z.string().nullable(),
    })),
    actionsTaken: z.array(z.strictObject({ text: z.string(), reportedBy: z.literal("requesting_agent"), verified: z.literal(false), flagged: z.boolean() })),
    nextSteps: z.array(z.string()),
    limitations: z.array(z.string()),
  }),
  markdown: z.string().max(200_000),
  narrative: narrativeSchema.nullable(),
  untrusted: untrustedSummarySchema,
});

type Input = z.infer<typeof input>;
type Output = z.infer<typeof output>;

export const securityReporting: SkillDefinition<Input, Output> = {
  name: "security_reporting",
  title: "Security Reporting",
  description: "Writes a security report from Legion findings: what happened, when, affected assets, risk, evidence, actions already taken and recommended next steps.",
  version: "1.0.0",
  input,
  output,
  capabilities: ["read:security_events", "read:assets"],
  auditEvents: ["skill.invoke"],
  usesModel: true,
  example: { alertIds: ["SEC-1A2B3C4D5E6F7A8B"], audience: "technical" },
  limitations: [
    "Facts come from Legion's alerts and asset inventory only; 'actions taken' are the requester's claims and are labelled unverified.",
    "Alert text is untrusted: in the Markdown it is escaped and links are defanged (hxxp://) so it cannot render as links or images.",
  ],
  async handler(ctx, q) {
    const ids = [...new Set(q.alertIds)];
    const events = (await ctx.data.securityEvents({ ids, limit: ids.length }))
      .filter((e) => ids.includes(e.id))
      .sort((a, b) => Date.parse(a.createdAt) - Date.parse(b.createdAt));
    if (!events.length) throw new SkillError("not_found", "None of these alerts exist.");

    const scored = events.map((e) => scoreEvent(ctx, e));
    const top = scored.reduce((m, s) => (s.score > m.score ? s : m), scored[0]!);
    const stages = [...new Set(events.flatMap((e) => readEvent(e).stages))].sort((a, b) => STAGES.indexOf(a) - STAGES.indexOf(b));
    const assetNames = [...new Set(events.map((e) => e.asset).filter((a): a is string => !!a))].slice(0, 100);
    const assets = assetNames.length ? await ctx.data.assets({ names: assetNames, limit: assetNames.length }) : [];
    const affectedAssets = assetNames.map((n) => ({ name: n, exposure: assets.find((a) => a.name === n)?.exposure ?? ("unknown" as const) }));

    const first = events[0]!.createdAt;
    const last = events[events.length - 1]!.createdAt;
    const whatHappened =
      `${events.length} security event(s) between ${first} and ${last}` +
      `${assetNames.length ? ` affecting ${assetNames.length} asset(s)` : ""}. ` +
      (stages.length ? `Activity observed: ${stages.map((s) => ATTACK_TYPES[s]).join("; ")}.` : "The events do not match a known attack pattern.");
    const riskReasons = [...new Set(top.reasons)];
    if (affectedAssets.some((a) => a.exposure === "internet")) riskReasons.push("At least one affected asset is internet-facing.");
    const actionsTaken = q.actionsTaken.map((t) => ({
      text: clip(t, 500), reportedBy: "requesting_agent" as const, verified: false as const,
      flagged: classifyContent({ source: "user_generated", content: t }).verdict !== "clean",
    }));
    const nextSteps = [...new Set(stages.flatMap((s) => INVESTIGATION_STEPS[s]))].slice(0, 8);
    if (!nextSteps.length) nextSteps.push("Review the raw events in Wazuh to determine whether they are benign.");
    if (ctx.untrusted().verdict !== "clean") nextSteps.unshift("Some alert text tries to instruct an AI reader (prompt injection); verify facts against raw logs.");
    const title = q.title ? clip(q.title, 200) : `Security report: ${clip(top.event.title, 120)}`;
    const report: Output["report"] = {
      title, generatedAt: ctx.now.toISOString(), audience: q.audience, whatHappened, when: { first, last }, affectedAssets,
      risk: { level: levelOf(top.score), score: top.score, reasons: riskReasons },
      evidence: events.slice(0, 100).map((e) => ({ eventId: e.id, time: e.createdAt, title: clip(e.title), severity: e.severity, asset: e.asset ?? null, sourceIp: e.sourceIp ?? null })),
      actionsTaken, nextSteps,
      limitations: [...securityReporting.limitations],
    };

    const md: string[] = [
      `# ${mdSafe(title)}`, "",
      `Generated ${report.generatedAt} by Legion. Audience: ${q.audience}.`, "",
      "## What happened", mdSafe(whatHappened), "",
      "## When", `First event: ${first}  `, `Last event: ${last}`, "",
      "## Affected assets", ...(affectedAssets.length ? affectedAssets.map((a) => `- ${mdSafe(a.name)} (exposure: ${a.exposure})`) : ["- None recorded"]), "",
      "## Risk", `**${report.risk.level.toUpperCase()}** (score ${report.risk.score}/100)`, ...riskReasons.map((r) => `- ${mdSafe(r)}`), "",
    ];
    if (q.audience === "technical") {
      md.push("## Evidence", "| Time | Event | Severity | Asset | Source IP |", "|---|---|---|---|---|",
        ...report.evidence.map((e) => `| ${e.time} | ${mdSafe(e.eventId)}: ${mdSafe(e.title)} | ${e.severity} | ${mdSafe(e.asset ?? "")} | ${mdSafe(e.sourceIp ?? "")} |`), "");
    }
    md.push("## Actions already taken (reported, not verified by Legion)",
      ...(actionsTaken.length ? actionsTaken.map((a) => `- ${mdSafe(a.text)}${a.flagged ? " _(flagged: contains instruction-like text)_" : ""}`) : ["- None reported"]), "",
      "## Recommended next steps", ...nextSteps.map((s, i) => `${i + 1}. ${mdSafe(s)}`), "");

    const narrative = q.narrative && ctx.modelAvailable
      ? await ctx.narrate({
        prompt: "skill.security_report",
        intent: `Write a ${q.audience} executive summary of this security report.`,
        trusted: { whatHappened, first, last, risk: report.risk.level, stages, assets: assetNames },
        untrusted: events.slice(0, 20).map((e) => ({ source: "security_alert" as const, id: e.id, text: eventText(e) })),
      }).catch(() => null)
      : null;
    if (narrative) md.push("## Summary (AI-generated, review before sharing)", mdSafe(narrative.text), "");

    return { report, markdown: md.join("\n"), narrative, untrusted: ctx.untrusted() };
  },
};
