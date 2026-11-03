import net from "node:net";
import { z } from "zod";
import { localIpFacts, STAGES } from "../knowledge.js";
import { proposedActionSchema, riskLevel, untrustedSummarySchema, type SkillDefinition } from "../types.js";
import { assemblyOf, clip, isoMinusHours, levelOf, propose, scoreEvent, type ScoredEvent } from "./common.js";

/*
 * Executor: which attacking addresses are worth blocking, with the evidence,
 * ready for a person to approve. It decides nothing and blocks nothing:
 * skills are read-only. The block itself is Dashboard → Defense (or the
 * perimeter firewall); Legion's automatic response uses the same limits.
 */

const SWARM_SOURCES = 10;

const input = z.strictObject({
  windowHours: z.number().int().min(1).max(168).default(24),
  minEvents: z.number().int().min(1).max(100).default(3),
});

const output = z.strictObject({
  window: z.strictObject({ from: z.string(), to: z.string() }),
  candidates: z.array(z.strictObject({
    ip: z.string(),
    riskLevel,
    score: z.number().int().min(0).max(100),
    eventCount: z.number().int(),
    stages: z.array(z.enum(STAGES)),
    targets: z.array(z.string()).max(20),
    firstSeen: z.string(),
    lastSeen: z.string(),
    reasons: z.array(z.string()).max(12),
    eventIds: z.array(z.string()).max(50),
  })).max(50),
  notBlockable: z.array(z.strictObject({ ip: z.string(), eventCount: z.number().int(), reason: z.string() })).max(50),
  warnings: z.array(z.string()).max(20),
  proposedActions: z.array(proposedActionSchema).max(20),
  untrusted: untrustedSummarySchema,
  limitations: z.array(z.string()),
});

type Input = z.infer<typeof input>;
type Output = z.infer<typeof output>;

export const containmentCandidates: SkillDefinition<Input, Output> = {
  name: "containment_candidates",
  agent: "Executor",
  title: "Containment Candidates",
  description: "Lists the attacking addresses worth blocking, with the evidence for each, separated from addresses that must not be blocked (private, loopback, documentation ranges). Warns when blocking would not help because many addresses attack one host. Recommends only; a person approves and performs the block.",
  version: "1.0.0",
  input,
  output,
  capabilities: ["read:security_events"],
  auditEvents: ["skill.invoke"],
  example: { windowHours: 24, minEvents: 3 },
  limitations: [
    "It blocks nothing. Skills are read-only; the block is made by an administrator (Dashboard → Defense) or at your firewall.",
    "Addresses in logs can be forged: someone who controls log text can name a victim's address. Confirm a candidate from a second source before blocking, and keep your own addresses on the allowlist.",
    "Blocking one address does not stop an attack from many addresses (a botnet); that needs protection at the network edge.",
    "A block is temporary by design. An attacker can return from another address.",
  ],
  async handler(ctx, q) {
    const to = ctx.now.toISOString();
    const from = isoMinusHours(ctx.now, q.windowHours);
    const events = await ctx.data.securityEvents({ since: from, until: to, limit: 500 });
    const scored = events.map((e) => scoreEvent(ctx, e));

    const perIp = new Map<string, ScoredEvent[]>();
    const sourcesPerTarget = new Map<string, Set<string>>();
    for (const s of scored) {
      const ip = s.event.sourceIp?.trim();
      if (!ip || net.isIP(ip) === 0) continue;
      perIp.set(ip, [...(perIp.get(ip) ?? []), s]);
      const target = s.event.asset?.trim();
      if (target) sourcesPerTarget.set(target, (sourcesPerTarget.get(target) ?? new Set()).add(ip));
    }

    const candidates: Output["candidates"] = [];
    const notBlockable: Output["notBlockable"] = [];
    for (const [ip, list] of perIp) {
      const facts = localIpFacts(ip);
      const best = Math.max(...list.map((s) => s.score));
      if (list.length < q.minEvents && best < 70) continue;
      if (facts.length) {
        notBlockable.push({ ip: clip(ip, 100), eventCount: list.length, reason: `${facts[0]}; do not block it.` });
        continue;
      }
      const sorted = [...list].sort((a, b) => a.event.createdAt.localeCompare(b.event.createdAt));
      const stages = [...new Set(sorted.flatMap((s) => s.reading.stages))].sort((a, b) => STAGES.indexOf(a) - STAGES.indexOf(b));
      const targets = [...new Set(sorted.map((s) => s.event.asset).filter((t): t is string => !!t))].slice(0, 20).map((t) => clip(t, 200));
      const score = Math.min(100, best + Math.min(20, 4 * (list.length - 1)) + (stages.length >= 3 ? 10 : 0));
      const reasons = [
        `${list.length} ${list.length === 1 ? "event" : "events"} from this public address${targets.length ? ` against ${targets.length} ${targets.length === 1 ? "asset" : "assets"}` : ""}.`,
        ...(stages.length >= 2 ? [`It moved through ${stages.length} attack stages (${stages.join(", ")}).`] : []),
        ...sorted.reduce<string[]>((acc, s) => (acc.length < 4 && s.score === best ? [...acc, ...s.reasons.slice(0, 2)] : acc), []),
      ];
      candidates.push({
        ip: clip(ip, 100), riskLevel: levelOf(score), score, eventCount: list.length, stages, targets,
        firstSeen: sorted[0]!.event.createdAt, lastSeen: sorted[sorted.length - 1]!.event.createdAt,
        reasons: [...new Set(reasons)].slice(0, 12), eventIds: sorted.map((s) => s.event.id).slice(0, 50),
      });
    }
    candidates.sort((a, b) => b.score - a.score);

    const warnings: string[] = [];
    for (const [target, sources] of sourcesPerTarget) {
      if (sources.size >= SWARM_SOURCES) {
        warnings.push(`${sources.size} different addresses are attacking ${clip(target, 150)}. Blocking addresses one by one will not stop this; use protection at the network edge (see EDGE-SECURITY.md).`);
      }
    }

    const top = candidates.slice(0, 10);
    const involved = new Set(top.flatMap((c) => c.eventIds));
    const assembly = assemblyOf(events.filter((e) => involved.has(e.id)));
    const proposedActions = top.map((c) => propose(assembly, {
      action: "block_source_ip", humanOnly: true, permission: null, destructive: false,
      description: `Block ${c.ip} for a limited time (Dashboard → Defense). Evidence: ${c.eventCount} events, risk ${c.riskLevel}. Verify the address in a second source first.`,
    }));

    return {
      window: { from, to },
      candidates: candidates.slice(0, 50),
      notBlockable: notBlockable.slice(0, 50),
      warnings: warnings.slice(0, 20),
      proposedActions,
      untrusted: ctx.untrusted(),
      limitations: [...containmentCandidates.limitations],
    };
  },
};
