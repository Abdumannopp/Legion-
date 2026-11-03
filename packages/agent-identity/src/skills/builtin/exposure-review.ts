import { z } from "zod";
import { proposedActionSchema, riskLevel, untrustedSummarySchema, type SkillDefinition, type Vulnerability } from "../types.js";
import { assemblyOf, clip, isoMinusHours, levelOf, propose } from "./common.js";

/*
 * Guardian: what is open to attack before anybody attacks it. An asset that
 * the internet can reach and that has a known, unpatched vulnerability is
 * the most likely way in; fixing it costs far less than the incident.
 */

const input = z.strictObject({
  limit: z.number().int().min(1).max(200).default(50),
  onlyInternetFacing: z.boolean().default(false),
});

const vulnerabilityOut = z.strictObject({
  id: z.string(),
  cve: z.string().nullable(),
  component: z.string(),
  severity: z.enum(["critical", "high", "medium", "low", "unknown"]),
  cvss: z.number().nullable(),
  fixedVersion: z.string().nullable(),
});

const output = z.strictObject({
  assets: z.array(z.strictObject({
    asset: z.string(),
    exposure: z.enum(["internet", "internal", "unknown"]),
    riskLevel,
    score: z.number().int().min(0).max(100),
    vulnerabilityCount: z.number().int(),
    topVulnerabilities: z.array(vulnerabilityOut).max(5),
    recentEvents: z.number().int(),
    reasons: z.array(z.string()),
    nextStep: z.string(),
  })).max(200),
  quickWins: z.array(z.strictObject({ asset: z.string(), component: z.string(), cve: z.string().nullable(), fixedVersion: z.string() })).max(20),
  summary: z.strictObject({
    assets: z.number().int(),
    internetFacing: z.number().int(),
    withCriticalOrHigh: z.number().int(),
    internetFacingWithCriticalOrHigh: z.number().int(),
  }),
  proposedActions: z.array(proposedActionSchema).max(20),
  untrusted: untrustedSummarySchema,
  limitations: z.array(z.string()),
});

type Input = z.infer<typeof input>;
type Output = z.infer<typeof output>;

type Sev = z.infer<typeof vulnerabilityOut>["severity"];

function severityOf(v: Vulnerability): Sev {
  if (typeof v.cvss === "number") return v.cvss >= 9 ? "critical" : v.cvss >= 7 ? "high" : v.cvss >= 4 ? "medium" : v.cvss > 0 ? "low" : "unknown";
  return v.severity ?? "unknown";
}

const SEV_POINTS: Record<Sev, number> = { critical: 35, high: 25, medium: 10, low: 3, unknown: 5 };
const SEV_RANK: Record<Sev, number> = { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 };

export const exposureReview: SkillDefinition<Input, Output> = {
  name: "exposure_review",
  agent: "Guardian",
  title: "Exposure Review",
  description: "Ranks the tenant's assets by how likely they are to be attacked successfully: reachable from the internet, carrying known vulnerabilities (with the fixed version when one exists) and already seeing security events. Gives the cheapest fixes first.",
  version: "1.0.0",
  input,
  output,
  capabilities: ["read:assets", "read:vulnerabilities", "read:security_events"],
  auditEvents: ["skill.invoke"],
  example: { limit: 50, onlyInternetFacing: false },
  limitations: [
    "Exposure comes from what the host reports; when it does not know, the asset is 'unknown' and scored lower, not safe.",
    "It reports only what a scanner found. A vulnerability no scanner reported is not in the result.",
    "It does not test whether a vulnerability can really be exploited on this asset.",
    "It never applies a patch or changes a firewall rule; its next steps are for a person.",
  ],
  async handler(ctx, q) {
    const now = ctx.now.toISOString();
    const [assets, vulns, events] = await Promise.all([
      ctx.data.assets({ limit: 200 }),
      ctx.data.vulnerabilities({ limit: 1_000 }),
      ctx.data.securityEvents({ since: isoMinusHours(ctx.now, 24 * 7), until: now, limit: 1_000 }),
    ]);

    const vulnsBy = new Map<string, Vulnerability[]>();
    for (const v of vulns) vulnsBy.set(v.asset.toLowerCase(), [...(vulnsBy.get(v.asset.toLowerCase()) ?? []), v]);
    const eventsBy = new Map<string, number>();
    for (const e of events) if (e.asset) eventsBy.set(e.asset.toLowerCase(), (eventsBy.get(e.asset.toLowerCase()) ?? 0) + 1);

    const rows: Output["assets"] = [];
    const quickWins: Output["quickWins"] = [];
    for (const a of assets) {
      if (q.onlyInternetFacing && a.exposure !== "internet") continue;
      const list = vulnsBy.get(a.name.toLowerCase()) ?? [];
      const ranked = list.map((v) => ({ v, sev: severityOf(v) })).sort((x, y) => SEV_RANK[y.sev] - SEV_RANK[x.sev]);
      const recent = eventsBy.get(a.name.toLowerCase()) ?? 0;

      const reasons: string[] = [];
      let score = 0;
      if (a.exposure === "internet") { score += 30; reasons.push("Reachable from the internet."); }
      else if (a.exposure === "unknown") { score += 10; reasons.push("Exposure is not known; assume it may be reachable."); }
      const vulnPoints = Math.min(60, ranked.reduce((n, r) => n + SEV_POINTS[r.sev], 0));
      if (ranked.length) {
        score += vulnPoints;
        const worst = ranked[0]!;
        reasons.push(`${ranked.length} known ${ranked.length === 1 ? "vulnerability" : "vulnerabilities"}, worst ${worst.sev}${worst.v.cve ? ` (${worst.v.cve})` : ""}.`);
      }
      if (recent) {
        score += Math.min(25, 5 * recent);
        reasons.push(`${recent} security ${recent === 1 ? "event" : "events"} on it in the last 7 days.`);
      }
      score = Math.min(100, score);

      const fixable = ranked.filter((r) => r.v.fixedVersion && (r.sev === "critical" || r.sev === "high" || a.exposure === "internet"));
      for (const r of fixable.slice(0, 3)) {
        quickWins.push({ asset: clip(a.name, 200), component: clip(r.v.component, 200), cve: r.v.cve ?? null, fixedVersion: clip(r.v.fixedVersion!, 100) });
      }
      const nextStep = !ranked.length
        ? a.exposure === "internet" ? "Nothing known is wrong. Keep it patched and watch it; confirm it needs to be reachable from the internet." : "No action needed from this review."
        : fixable.length ? `Update ${clip(fixable[0]!.v.component, 100)} to ${clip(fixable[0]!.v.fixedVersion!, 60)}${a.exposure === "internet" ? " first: it is reachable from the internet" : ""}.`
        : "No fixed version is recorded. Find the vendor's mitigation, or restrict access to this asset.";
      rows.push({
        asset: clip(a.name, 200), exposure: a.exposure, riskLevel: levelOf(score), score, vulnerabilityCount: ranked.length,
        topVulnerabilities: ranked.slice(0, 5).map(({ v, sev }) => ({ id: clip(v.id, 200), cve: v.cve ?? null, component: clip(v.component, 200), severity: sev, cvss: v.cvss ?? null, fixedVersion: v.fixedVersion ? clip(v.fixedVersion, 100) : null })),
        recentEvents: recent, reasons, nextStep,
      });
    }
    rows.sort((x, y) => y.score - x.score);

    const serious = (r: Output["assets"][number]) => r.topVulnerabilities.some((v) => v.severity === "critical" || v.severity === "high");
    const top = rows.filter((r) => r.score >= 50).slice(0, 5);
    const assembly = assemblyOf(events.filter((e) => e.asset && top.some((t) => t.asset.toLowerCase() === e.asset!.toLowerCase())).slice(0, 50));
    const proposedActions: Output["proposedActions"] = top.flatMap((r) => [
      propose(assembly, { action: "apply_patch", humanOnly: true, permission: null, destructive: false, description: `${r.nextStep} (${r.asset})` }),
      ...(r.exposure === "internet" && serious(r)
        ? [propose(assembly, { action: "restrict_exposure", humanOnly: true, permission: null, destructive: false, description: `Until it is patched, limit who can reach ${r.asset} (firewall rule, VPN, or a WAF in front of it).` })]
        : []),
    ]).slice(0, 20);

    return {
      assets: rows.slice(0, q.limit),
      quickWins: quickWins.slice(0, 20),
      summary: {
        assets: rows.length,
        internetFacing: rows.filter((r) => r.exposure === "internet").length,
        withCriticalOrHigh: rows.filter(serious).length,
        internetFacingWithCriticalOrHigh: rows.filter((r) => r.exposure === "internet" && serious(r)).length,
      },
      proposedActions,
      untrusted: ctx.untrusted(),
      limitations: [...exposureReview.limitations],
    };
  },
};
