import { z } from "zod";
import { localIpFacts, mentions, normalizeIndicator, type Indicator } from "../knowledge.js";
import { INDICATOR_TYPES, SEVERITIES, SEVERITY_RANK, SkillError, untrustedSummarySchema, type IntelResult, type SkillDefinition } from "../types.js";
import { clip, isoMinusHours } from "./common.js";

const input = z.strictObject({
  indicators: z.array(z.strictObject({ value: z.string().min(1).max(2_048), type: z.enum(INDICATOR_TYPES).optional() })).min(1).max(50),
  includeSightings: z.boolean().default(true),
});

const VERDICTS = ["known_malicious", "suspicious", "unknown", "known_safe"] as const;

const output = z.strictObject({
  providerStatus: z.enum(["ok", "not_configured", "unavailable"]),
  results: z.array(z.strictObject({
    indicator: z.strictObject({ type: z.enum(INDICATOR_TYPES), value: z.string() }),
    verdict: z.enum(VERDICTS),
    reasons: z.array(z.string()),
    sources: z.array(z.strictObject({
      source: z.string(), verdict: z.enum(["malicious", "suspicious", "benign", "unknown"]), confidence: z.number().nullable(),
      lastSeen: z.string().nullable(), notes: z.string().nullable(),
    })),
    localFacts: z.array(z.string()),
    sightings: z.strictObject({ count: z.number().int(), eventIds: z.array(z.string()), maxSeverity: z.enum(SEVERITIES).nullable() }).nullable(),
  })),
  rejected: z.array(z.strictObject({ value: z.string(), reason: z.string() })),
  untrusted: untrustedSummarySchema,
});

type Input = z.infer<typeof input>;
type Output = z.infer<typeof output>;

/**
 * The verdict comes only from intelligence sources. No source, no opinion:
 * the indicator is "unknown", never guessed from its shape or from Legion's
 * own sightings (being seen in an alert is not being malicious).
 */
function verdictFrom(results: IntelResult[]): { verdict: (typeof VERDICTS)[number]; reasons: string[] } {
  if (!results.length) return { verdict: "unknown", reasons: ["No threat-intelligence source returned information for this indicator. Legion does not guess."] };
  const mal = results.filter((r) => r.verdict === "malicious").map((r) => r.source);
  const sus = results.filter((r) => r.verdict === "suspicious").map((r) => r.source);
  const ben = results.filter((r) => r.verdict === "benign").map((r) => r.source);
  if (mal.length && ben.length) return { verdict: "suspicious", reasons: [`Sources disagree: malicious per ${mal.join(", ")}, benign per ${ben.join(", ")}.`] };
  if (mal.length) return { verdict: "known_malicious", reasons: [`Reported malicious by ${mal.join(", ")}.`] };
  if (sus.length) return { verdict: "suspicious", reasons: [`Reported suspicious by ${sus.join(", ")}.`] };
  if (ben.length) return { verdict: "known_safe", reasons: [`Reported benign by ${ben.join(", ")}.`] };
  return { verdict: "unknown", reasons: ["Sources answered but had no verdict for this indicator."] };
}

export const threatIntelligence: SkillDefinition<Input, Output> = {
  name: "threat_intelligence",
  title: "Threat Intelligence",
  description: "Enriches IPs, domains, URLs, file hashes, CVEs and email addresses with the configured threat-intelligence provider and Legion's own sightings, classifying each as known malicious, suspicious, unknown or known safe.",
  version: "1.0.0",
  input,
  output,
  capabilities: ["read:threat_intel", "read:security_events"],
  auditEvents: ["skill.invoke"],
  example: { indicators: [{ value: "203.0.113.7" }, { value: "CVE-2021-44228", type: "cve" }] },
  limitations: [
    "Legion has no intelligence of its own: without a configured provider every verdict is 'unknown'.",
    "The skill never resolves, fetches or connects to an indicator; lookups happen only in the host's provider.",
    "Provider notes are untrusted text and are withheld when they look like instructions.",
  ],
  async handler(ctx, q) {
    const rejected: Output["rejected"] = [];
    const list: Indicator[] = [];
    const seen = new Set<string>();
    for (const raw of q.indicators) {
      const n = normalizeIndicator(raw.value, raw.type);
      if (!n) { rejected.push({ value: clip(raw.value, 100), reason: raw.type ? `not a valid ${raw.type}` : "not a recognised indicator" }); continue; }
      const k = `${n.type}:${n.value}`;
      if (!seen.has(k)) { seen.add(k); list.push(n); }
    }

    let providerStatus: Output["providerStatus"] = "ok";
    let intel: IntelResult[] = [];
    if (list.length) {
      try {
        intel = await ctx.data.lookupIndicators(list);
      } catch (err) {
        // Missing or failing provider: say so, and answer "unknown". A
        // provider that returns malformed or foreign data fails the skill.
        if (!(err instanceof SkillError) || err.code !== "data_unavailable") throw err;
        providerStatus = err.details.reason === "not_configured" ? "not_configured" : "unavailable";
      }
    }

    const events = q.includeSightings && list.length
      ? await ctx.data.securityEvents({ since: isoMinusHours(ctx.now, 24 * 30), limit: 500 })
      : null;

    const results: Output["results"] = list.map((ind) => {
      const mine = intel.filter((r) => r.type === ind.type && r.indicator === ind.value);
      const { verdict, reasons } = verdictFrom(mine);
      if (providerStatus !== "ok") reasons.push(providerStatus === "not_configured" ? "No threat-intelligence provider is configured." : "The threat-intelligence provider could not be reached.");
      const hits = events ? events.filter((e) => mentions(e, ind.value)) : null;
      if (hits?.length) reasons.push(`Seen in ${hits.length} Legion alert(s) in the last 30 days — context, not a verdict.`);
      return {
        indicator: { type: ind.type, value: ind.value },
        verdict,
        reasons,
        sources: mine.map((r) => ({
          source: r.source, verdict: r.verdict, confidence: r.confidence ?? null, lastSeen: r.lastSeen ?? null,
          notes: r.notes
            ? ctx.verdictOf(`intel:${r.type}:${r.indicator}`) === "clean" ? clip(r.notes, 500) : "[withheld: the provider's note contained instruction-like content]"
            : null,
        })),
        localFacts: ind.type === "ip" ? localIpFacts(ind.value) : [],
        sightings: hits
          ? {
            count: hits.length, eventIds: hits.slice(0, 10).map((e) => e.id),
            maxSeverity: hits.reduce<(typeof SEVERITIES)[number] | null>((m, e) => (!m || SEVERITY_RANK[e.severity] > SEVERITY_RANK[m] ? e.severity : m), null),
          }
          : null,
      };
    });
    return { providerStatus, results, rejected, untrusted: ctx.untrusted() };
  },
};
