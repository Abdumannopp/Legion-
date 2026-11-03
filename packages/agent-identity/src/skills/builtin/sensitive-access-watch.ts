import { z } from "zod";
import { proposedActionSchema, riskLevel, untrustedSummarySchema, type SecurityEvent, type SkillDefinition } from "../types.js";
import { assemblyOf, clip, isoMinusHours, levelOf, propose } from "./common.js";

/*
 * Sentinel: who is reading the data that matters (customer records, payroll,
 * contracts, keys, backups). One person opening a few files is work; one
 * account opening dozens, or touching them on several machines, is how data
 * leaves a company, whether the account belongs to a thief or to an insider.
 */

const BROAD_FILES = 10;
const MANY_HOSTS = 3;

/** Names that say a path or event is about data worth protecting. */
export const SENSITIVE_RE = /(?:\b(?:customers?|clients?|payroll|salar(?:y|ies)|hr[-_ ]?records?|employees?|invoices?|contracts?|passports?|medical|patients?|credit[-_ ]?cards?|iban|accounts?[-_ ]?receivable|finance|financial|tax|secrets?|credentials?|backups?|dumps?)\b|\.(?:pem|key|pfx|p12|kdbx|ovpn)\b|id_rsa|\.sql\b|\.bak\b)/i;

/** File access shown by the sensor: a path, or words saying a file or record was read. */
const ACCESS_RE = /\b(?:file (?:was )?(?:read|opened|accessed|copied|downloaded)|read access|opened file|object (?:accessed|read)|select\b[^\n]{0,80}\bfrom\b|exported?|download(?:ed)?)\b/i;

const input = z.strictObject({
  windowHours: z.number().int().min(1).max(168).default(24),
  limit: z.number().int().min(1).max(1_000).default(500),
});

const output = z.strictObject({
  window: z.strictObject({ from: z.string(), to: z.string() }),
  eventsAnalyzed: z.number().int(),
  sensitiveEvents: z.number().int(),
  accounts: z.array(z.strictObject({
    who: z.string(),
    kind: z.enum(["account", "address", "asset"]),
    riskLevel,
    score: z.number().int().min(0).max(100),
    distinctItems: z.number().int(),
    distinctAssets: z.number().int(),
    patterns: z.array(z.string()),
    reasons: z.array(z.string()),
    examples: z.array(z.string()).max(5),
    eventIds: z.array(z.string()).max(50),
  })).max(50),
  overallRisk: riskLevel,
  proposedActions: z.array(proposedActionSchema).max(20),
  untrusted: untrustedSummarySchema,
  limitations: z.array(z.string()),
});

type Input = z.infer<typeof input>;
type Output = z.infer<typeof output>;

/** What the event touched: its path, or the sensitive word that made it count. */
function itemOf(e: SecurityEvent): string | null {
  if (e.filePath && SENSITIVE_RE.test(e.filePath)) return e.filePath;
  const text = `${e.title}\n${e.summary}`;
  if (!SENSITIVE_RE.test(text) || !ACCESS_RE.test(text)) return null;
  const path = /(?:\/[\w.@%+~-]+){2,}|[A-Za-z]:\\[^\s"']+/.exec(text)?.[0];
  return path ?? `${SENSITIVE_RE.exec(text)![0].toLowerCase()} (${e.id})`;
}

export const sensitiveAccessWatch: SkillDefinition<Input, Output> = {
  name: "sensitive_access_watch",
  agent: "Sentinel",
  title: "Sensitive Access Watch",
  description: "Watches who opens the data that matters (customer records, payroll, contracts, keys, backups). Flags an account that opens many different sensitive items or reaches them on several machines. Names the account and what it touched.",
  version: "1.0.0",
  input,
  output,
  capabilities: ["read:security_events"],
  auditEvents: ["skill.invoke"],
  example: { windowHours: 24 },
  limitations: [
    "It only sees file and record access that a sensor reports (file integrity monitoring, audit logs, database audit). Without such events it sees nothing, and it will say 0 rather than 'safe'.",
    "It judges by names: a path or event must contain a word like customers, payroll or backup to count. Sensitive data kept under a neutral name is missed, and a harmless folder named 'finance' counts.",
    "There is no baseline of what is normal for each person. A finance employee opening many finance files is normal; the result is a lead to check with the data's owner, not proof of misuse.",
    "It does not stop anything. Revoking access is for a person.",
  ],
  async handler(ctx, q) {
    const to = ctx.now.toISOString();
    const from = isoMinusHours(ctx.now, q.windowHours);
    const events = await ctx.data.securityEvents({ since: from, until: to, limit: q.limit });

    interface Group { kind: "account" | "address" | "asset"; who: string; items: Set<string>; assets: Set<string>; ids: string[] }
    const groups = new Map<string, Group>();
    let sensitive = 0;
    for (const e of events) {
      const item = itemOf(e);
      if (!item) continue;
      sensitive++;
      const [kind, who] = e.user?.trim() ? (["account", e.user.trim()] as const)
        : e.sourceIp ? (["address", e.sourceIp] as const)
        : (["asset", e.asset ?? "unknown"] as const);
      const key = `${kind}:${who.toLowerCase()}`;
      const g = groups.get(key) ?? { kind, who: clip(who, 200), items: new Set(), assets: new Set(), ids: [] };
      g.items.add(clip(item, 200).toLowerCase());
      if (e.asset) g.assets.add(e.asset.toLowerCase());
      g.ids.push(e.id);
      groups.set(key, g);
    }

    const accounts: Output["accounts"] = [];
    for (const g of groups.values()) {
      const patterns: string[] = [];
      const reasons: string[] = [];
      let score = 0;
      if (g.items.size >= BROAD_FILES) {
        patterns.push("broad_access");
        reasons.push(`${g.items.size} different sensitive items opened in ${q.windowHours} hour(s).`);
        score += 40 + Math.min(30, 2 * (g.items.size - BROAD_FILES));
      }
      if (g.assets.size >= MANY_HOSTS) {
        patterns.push("many_hosts");
        reasons.push(`Sensitive data reached on ${g.assets.size} different machines.`);
        score += 25;
      }
      if (!patterns.length) continue;
      if (g.kind === "address") { patterns.push("unknown_account"); reasons.push("The sensor did not say which account; only the address is known."); score += 10; }
      score = Math.min(100, score);
      accounts.push({
        who: g.who, kind: g.kind, riskLevel: levelOf(score), score, distinctItems: g.items.size, distinctAssets: g.assets.size,
        patterns, reasons, examples: [...g.items].slice(0, 5), eventIds: g.ids.slice(0, 50),
      });
    }
    accounts.sort((a, b) => b.score - a.score);

    // Every flagged account gets a review for a person: it is only a recommendation.
    const top = accounts.slice(0, 5);
    const involved = new Set(top.flatMap((a) => a.eventIds));
    const assembly = assemblyOf(events.filter((e) => involved.has(e.id)).slice(0, 50));
    const proposedActions = top.map((a) => propose(assembly, {
      action: a.kind === "account" ? "review_access" : "investigate_source", humanOnly: true, permission: null, destructive: false,
      description: a.kind === "account"
        ? `Ask the owner of the data whether ${a.who} should be opening ${a.distinctItems} sensitive items. If not, suspend the account and reset its password.`
        : `Find out which account is behind ${a.who} and whether it should reach this data.`,
    }));
    return {
      window: { from, to },
      eventsAnalyzed: events.length,
      sensitiveEvents: sensitive,
      accounts: accounts.slice(0, 50),
      overallRisk: levelOf(Math.max(0, ...accounts.map((a) => a.score))),
      proposedActions,
      untrusted: ctx.untrusted(),
      limitations: [...sensitiveAccessWatch.limitations],
    };
  },
};
