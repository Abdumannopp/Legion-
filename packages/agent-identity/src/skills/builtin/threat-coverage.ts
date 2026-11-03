import { z } from "zod";
import { assessCoverage } from "../coverage.js";
import { THREATS } from "../threats.js";
import { untrustedSummarySchema, type SkillDefinition } from "../types.js";
import { eventText, isoMinusHours } from "./common.js";

/*
 * Guardian: for the seven most dangerous attack types — ransomware, business
 * email compromise, phishing, DDoS, AI deception, espionage, supply chain —
 * what Legion has seen, what it is watching, and where it is blind because
 * the data never arrives.
 */

const input = z.strictObject({
  windowDays: z.number().int().min(1).max(30).default(7),
});

const output = z.strictObject({
  window: z.strictObject({ from: z.string(), to: z.string() }),
  eventsAnalyzed: z.number().int(),
  threats: z.array(z.strictObject({
    threat: z.enum(THREATS),
    status: z.enum(["detected", "watching", "blind", "partial"]),
    detections: z.number().int(),
    lastSeen: z.string().nullable(),
    signs: z.array(z.strictObject({ id: z.string(), label: z.string(), count: z.number().int() })),
    eventIds: z.array(z.string()).max(10),
    sourceSeen: z.boolean(),
    connect: z.string(),
  })).length(THREATS.length),
  blind: z.array(z.enum(THREATS)),
  untrusted: untrustedSummarySchema,
  limitations: z.array(z.string()),
});

type Input = z.infer<typeof input>;
type Output = z.infer<typeof output>;

export const threatCoverage: SkillDefinition<Input, Output> = {
  name: "threat_coverage",
  agent: "Guardian",
  title: "Threat Coverage",
  description: "For the seven most dangerous attack types (ransomware, business email compromise, phishing, DDoS, AI deception, cyber espionage, supply chain): what Legion detected, what it is watching, and where it is blind because the data it needs never arrives — with what to connect.",
  version: "1.0.0",
  input,
  output,
  capabilities: ["read:security_events"],
  auditEvents: ["skill.invoke"],
  example: { windowDays: 7 },
  limitations: [
    "It reads at most the 500 most recent events in the window; on a busy workspace an older detection can be outside them.",
    "'Watching' means the right kind of data arrives and no sign was found. It is not a guarantee that nothing happened.",
    "A deepfake call or video never reaches Legion. It can only see what follows one: a changed payment detail, a new forwarding rule.",
    "Legion does not stop a DDoS on your own site; an edge service such as Cloudflare does. Legion sees it in the logs and protects itself.",
  ],
  async handler(ctx, q) {
    const to = ctx.now.toISOString();
    const from = isoMinusHours(ctx.now, q.windowDays * 24);
    const events = await ctx.data.securityEvents({ since: from, until: to, limit: 500 });
    const threats = assessCoverage(
      events.map((e) => ({ id: e.id, createdAt: e.createdAt, text: eventText(e) })),
      { aiTextAttempts: events.filter((e) => ctx.verdictOf(e.id) !== "clean").map((e) => e.id) },
    );
    return {
      window: { from, to },
      eventsAnalyzed: events.length,
      threats,
      blind: threats.filter((t) => t.status === "blind").map((t) => t.threat),
      untrusted: ctx.untrusted(),
      limitations: [...threatCoverage.limitations],
    };
  },
};
