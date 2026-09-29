import { z } from "zod";
import { primaryStage, readEvent, STAGE_ORDER, STAGES, type Stage } from "../knowledge.js";
import { SEVERITIES, SkillError, untrustedSummarySchema, type SecurityEvent, type SkillDefinition } from "../types.js";
import { clip, isoMinusHours } from "./common.js";

const input = z.strictObject({
  alertIds: z.array(z.string().min(1).max(200)).min(1).max(200).optional(),
  windowHours: z.number().int().min(1).max(168).default(24),
  asset: z.string().min(1).max(300).optional(),
  sourceIp: z.string().min(1).max(100).optional(),
  /** Two events are linked only if they share an entity and happened within this many minutes of each other. */
  maxGapMinutes: z.number().int().min(1).max(1_440).default(240),
});

const output = z.strictObject({
  window: z.strictObject({ from: z.string(), to: z.string() }),
  eventsAnalyzed: z.number().int(),
  timeline: z.array(z.strictObject({
    eventId: z.string(), time: z.string(), stage: z.enum(STAGES).nullable(), title: z.string(), severity: z.enum(SEVERITIES),
    asset: z.string().nullable(), sourceIp: z.string().nullable(), user: z.string().nullable(),
  })).max(500),
  chains: z.array(z.strictObject({
    id: z.string(),
    stages: z.array(z.enum(STAGES)),
    eventIds: z.array(z.string()),
    assets: z.array(z.string()),
    sourceIps: z.array(z.string()),
    users: z.array(z.string()),
    firstSeen: z.string(),
    lastSeen: z.string(),
    confidence: z.enum(["low", "medium", "high"]),
    reasons: z.array(z.string()),
  })).max(50),
  affectedAssets: z.array(z.strictObject({ name: z.string(), exposure: z.enum(["internet", "internal", "unknown"]), os: z.string().nullable() })),
  unlinkedEventIds: z.array(z.string()),
  untrusted: untrustedSummarySchema,
});

type Input = z.infer<typeof input>;
type Output = z.infer<typeof output>;

function entities(e: SecurityEvent): string[] {
  return [e.asset && `asset:${e.asset}`, e.sourceIp && `ip:${e.sourceIp}`, e.user && `user:${e.user}`].filter((x): x is string => !!x);
}

export const attackInvestigation: SkillDefinition<Input, Output> = {
  name: "attack_investigation",
  title: "Attack Investigation",
  description: "Connects related security events into possible attack chains (e.g. failed logins → successful login → unusual process → network connection → file change) with a timeline, stages, affected assets and a confidence level.",
  version: "1.0.0",
  input,
  output,
  capabilities: ["read:security_events", "read:assets"],
  auditEvents: ["skill.invoke"],
  example: { windowHours: 24, asset: "web-01" },
  limitations: [
    "Events are linked only when they share an asset, source IP or user within the time gap; an attacker who changes all three is not linked.",
    "A chain is a hypothesis for an analyst to confirm, not proof of compromise.",
  ],
  async handler(ctx, q) {
    const to = ctx.now.toISOString();
    const from = isoMinusHours(ctx.now, q.windowHours);
    const events = (await ctx.data.securityEvents(
      q.alertIds ? { ids: q.alertIds, limit: q.alertIds.length } : { since: from, until: to, asset: q.asset, sourceIp: q.sourceIp, limit: 500 },
    )).sort((a, b) => Date.parse(a.createdAt) - Date.parse(b.createdAt));
    if (q.alertIds && !events.length) throw new SkillError("not_found", "None of these alerts exist.");

    const stageOf = new Map(events.map((e) => [e.id, primaryStage(readEvent(e))] as const));
    const timeline: Output["timeline"] = events.map((e) => ({
      eventId: e.id, time: e.createdAt, stage: stageOf.get(e.id) ?? null, title: clip(e.title), severity: e.severity,
      asset: e.asset ?? null, sourceIp: e.sourceIp ?? null, user: e.user ?? null,
    }));

    // Union-find: link events that share an entity and are close in time.
    const parent = events.map((_, i) => i);
    const find = (i: number): number => (parent[i] === i ? i : (parent[i] = find(parent[i]!)));
    const gap = q.maxGapMinutes * 60_000;
    for (let i = 0; i < events.length; i++) {
      const ei = new Set(entities(events[i]!));
      for (let j = i + 1; j < events.length; j++) {
        if (Date.parse(events[j]!.createdAt) - Date.parse(events[i]!.createdAt) > gap) break;
        const shared = entities(events[j]!).filter((x) => ei.has(x));
        if (shared.length) parent[find(j)] = find(i);
      }
    }
    const components = new Map<number, SecurityEvent[]>();
    events.forEach((e, i) => {
      const r = find(i);
      components.set(r, [...(components.get(r) ?? []), e]);
    });

    const chains: Output["chains"] = [];
    const linked = new Set<string>();
    for (const list of components.values()) {
      const staged = list.filter((e) => stageOf.get(e.id));
      const stagesInTime = staged.map((e) => stageOf.get(e.id)!) as Stage[];
      const distinct = [...new Set(stagesInTime)];
      if (list.length < 2 || distinct.length < 2) continue;
      let forward = 0;
      for (let k = 1; k < stagesInTime.length; k++) if (STAGE_ORDER[stagesInTime[k]!] >= STAGE_ORDER[stagesInTime[k - 1]!]) forward++;
      const ordered = stagesInTime.length > 1 ? forward / (stagesInTime.length - 1) : 0;
      const assets = [...new Set(list.map((e) => e.asset).filter((x): x is string => !!x))];
      const ips = [...new Set(list.map((e) => e.sourceIp).filter((x): x is string => !!x))];
      const users = [...new Set(list.map((e) => e.user).filter((x): x is string => !!x))];
      const reasons = [
        `${list.length} events linked by a shared ${[assets.length ? "asset" : "", ips.length ? "source IP" : "", users.length ? "user" : ""].filter(Boolean).join(" / ")} within ${q.maxGapMinutes} minutes of each other.`,
        `${distinct.length} attack stages: ${distinct.join(" → ")}.`,
        `${Math.round(ordered * 100)}% of steps move forward through the usual attack order.`,
      ];
      if (list.some((e) => ctx.verdictOf(e.id) !== "clean")) reasons.push("Some of these events contain prompt-injection text; their content was treated as data.");
      const confidence = distinct.length >= 3 && ordered >= 0.7 && assets.length <= 1 ? "high" : distinct.length >= 2 && ordered >= 0.5 ? "medium" : "low";
      list.forEach((e) => linked.add(e.id));
      chains.push({
        id: `chain-${chains.length + 1}`,
        stages: distinct.sort((a, b) => STAGE_ORDER[a] - STAGE_ORDER[b]),
        eventIds: list.map((e) => e.id),
        assets, sourceIps: ips, users,
        firstSeen: list[0]!.createdAt, lastSeen: list[list.length - 1]!.createdAt,
        confidence, reasons,
      });
    }
    chains.sort((a, b) => ({ high: 3, medium: 2, low: 1 }[b.confidence] - { high: 3, medium: 2, low: 1 }[a.confidence]) || b.eventIds.length - a.eventIds.length);

    const assetNames = [...new Set(chains.flatMap((c) => c.assets))].slice(0, 100);
    const assets = assetNames.length ? await ctx.data.assets({ names: assetNames, limit: assetNames.length }) : [];
    return {
      window: q.alertIds ? { from: events[0]?.createdAt ?? to, to: events[events.length - 1]?.createdAt ?? to } : { from, to },
      eventsAnalyzed: events.length,
      timeline,
      chains: chains.slice(0, 50),
      affectedAssets: assetNames.map((n) => {
        const a = assets.find((x) => x.name === n);
        return { name: n, exposure: a?.exposure ?? "unknown", os: a?.os ?? null };
      }),
      unlinkedEventIds: events.filter((e) => !linked.has(e.id)).map((e) => e.id),
      untrusted: ctx.untrusted(),
    };
  },
};
