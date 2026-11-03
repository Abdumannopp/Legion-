import { z } from "zod";
import { findSecrets } from "../../firewall/scan.js";
import { proposedActionSchema, untrustedSummarySchema, riskLevel, type SkillDefinition } from "../types.js";
import { assemblyOf, clip, eventText, isoMinusHours, propose } from "./common.js";

/*
 * Guardian: credentials, card numbers and bank account numbers that ended up
 * in logs. Whoever can read the logs can use them, and logs are copied to
 * many places (the sensor, Legion, backups, a ticket). Reports WHAT kind and
 * WHERE; never the value itself.
 */

/** Luhn check: a run of digits is only called a card number if it is one. */
export function luhnValid(digits: string): boolean {
  if (!/^\d{13,19}$/.test(digits)) return false;
  let sum = 0;
  for (let i = 0; i < digits.length; i++) {
    let d = Number(digits[digits.length - 1 - i]);
    if (i % 2 === 1) { d *= 2; if (d > 9) d -= 9; }
    sum += d;
  }
  return sum % 10 === 0;
}

/** IBAN check (mod 97), so an ordinary reference number is not mistaken for one. */
export function ibanValid(raw: string): boolean {
  const iban = raw.replace(/\s/g, "").toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(iban)) return false;
  const moved = iban.slice(4) + iban.slice(0, 4);
  let rem = 0;
  for (const ch of moved) {
    const v = ch >= "A" ? String(ch.charCodeAt(0) - 55) : ch;
    for (const c of v) rem = (rem * 10 + Number(c)) % 97;
  }
  return rem === 1;
}

const LABEL: Record<string, string> = {
  private_key: "Private key",
  aws_access_key: "Cloud access key (AWS)",
  github_token: "Code-hosting token",
  slack_token: "Chat token",
  llm_api_key: "AI service key",
  jwt: "Sign-in token (JWT)",
  legion_credential: "Legion credential",
  legion_access_token: "Legion access token",
  plaintext_password: "Password or secret written in plain text",
  card_number: "Payment card number",
  iban: "Bank account number (IBAN)",
};
const ADVICE: Record<string, string> = {
  private_key: "Treat the key as stolen: replace it everywhere it is trusted, then stop the system that logs it.",
  aws_access_key: "Deactivate and rotate the key in the cloud console now, then check its recent activity.",
  github_token: "Revoke the token in the code-hosting settings and issue a new one.",
  slack_token: "Revoke the token in the chat workspace settings.",
  llm_api_key: "Revoke the key with the AI provider and issue a new one.",
  jwt: "Sign the user out everywhere and shorten token lifetimes; the token works until it expires.",
  legion_credential: "Rotate the credential in Legion (Connect).",
  legion_access_token: "Suspend or revoke the agent in Legion (AI agents).",
  plaintext_password: "Change that password, then stop the application from logging it.",
  card_number: "Card numbers must not be in logs (card-industry rules). Remove them from the log source and the stored copies; tell whoever handles your card compliance.",
  iban: "Bank account numbers are personal data. Limit who can read these logs and stop the source from logging them.",
};
const SEVERITY: Record<string, z.infer<typeof riskLevel>> = {
  private_key: "critical", aws_access_key: "critical", github_token: "high", slack_token: "high", llm_api_key: "high",
  jwt: "medium", legion_credential: "critical", legion_access_token: "high", plaintext_password: "high", card_number: "high", iban: "medium",
};

const CARD_RE = /(?<![\d-])(?:\d[ -]?){13,19}(?![\d-])/g;
const IBAN_RE = /\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?\b/g;
const PASSWORD_RE = /\b(?:password|passwd|pwd|secret|api[_-]?key|token)\s*[=:]\s*["']?(?!\*{3}|\[redacted|<|null\b|none\b|true\b|false\b)[^\s"',;&]{6,}/i;

/** The kinds of sensitive value in a text. Values are never returned. */
export function sensitiveKinds(text: string): string[] {
  const t = String(text ?? "").slice(0, 20_000);
  const kinds = new Set<string>(findSecrets(t));
  if (PASSWORD_RE.test(t)) kinds.add("plaintext_password");
  for (const m of t.matchAll(CARD_RE)) if (luhnValid(m[0].replace(/[ -]/g, ""))) { kinds.add("card_number"); break; }
  for (const m of t.matchAll(IBAN_RE)) if (ibanValid(m[0])) { kinds.add("iban"); break; }
  return [...kinds];
}

const input = z.strictObject({
  windowHours: z.number().int().min(1).max(720).default(168),
  limit: z.number().int().min(1).max(500).default(500),
});

const output = z.strictObject({
  window: z.strictObject({ from: z.string(), to: z.string() }),
  eventsAnalyzed: z.number().int(),
  findings: z.array(z.strictObject({
    kind: z.string(),
    label: z.string(),
    riskLevel,
    count: z.number().int(),
    assets: z.array(z.string()).max(20),
    eventIds: z.array(z.string()).max(20),
    firstSeen: z.string(),
    lastSeen: z.string(),
    advice: z.string(),
  })).max(20),
  overallRisk: riskLevel,
  proposedActions: z.array(proposedActionSchema).max(20),
  untrusted: untrustedSummarySchema,
  limitations: z.array(z.string()),
});

type Input = z.infer<typeof input>;
type Output = z.infer<typeof output>;
const RANK = { low: 1, medium: 2, high: 3, critical: 4 } as const;

export const secretExposureCheck: SkillDefinition<Input, Output> = {
  name: "secret_exposure_check",
  agent: "Guardian",
  title: "Secret Exposure Check",
  description: "Finds credentials, payment card numbers and bank account numbers that have ended up in security logs, and says what kind, how many, on which assets, and what to do. Never shows the value itself.",
  version: "1.0.0",
  input,
  output,
  capabilities: ["read:security_events"],
  auditEvents: ["skill.invoke"],
  example: { windowHours: 168 },
  limitations: [
    "It reads only the events Legion received (the 500 most recent in the window). A secret in a log Legion never receives is not seen.",
    "It recognises well-known formats and checksummed numbers (card numbers, IBANs). A homemade secret or an unusual format is missed, and a plain password is guessed from words like 'password=' and can be wrong.",
    "It reports the kind and the place, never the value, and it cannot tell whether the secret is still valid.",
    "It does not remove anything. Cleaning the log source and rotating the secret are for a person.",
  ],
  async handler(ctx, q) {
    const to = ctx.now.toISOString();
    const from = isoMinusHours(ctx.now, q.windowHours);
    const events = await ctx.data.securityEvents({ since: from, until: to, limit: q.limit });
    const byKind = new Map<string, { ids: string[]; assets: Set<string>; times: string[] }>();
    for (const e of events) {
      for (const kind of sensitiveKinds(eventText(e))) {
        const entry = byKind.get(kind) ?? { ids: [], assets: new Set<string>(), times: [] };
        entry.ids.push(e.id);
        if (e.asset) entry.assets.add(clip(e.asset, 200));
        entry.times.push(e.createdAt);
        byKind.set(kind, entry);
      }
    }
    const findings = [...byKind].map(([kind, v]) => {
      const times = [...v.times].sort();
      return {
        kind, label: LABEL[kind] ?? kind, riskLevel: SEVERITY[kind] ?? "medium", count: v.ids.length,
        assets: [...v.assets].slice(0, 20), eventIds: v.ids.slice(0, 20), firstSeen: times[0]!, lastSeen: times[times.length - 1]!,
        advice: ADVICE[kind] ?? "Remove it from the log source and rotate it.",
      };
    }).sort((a, b) => RANK[b.riskLevel] - RANK[a.riskLevel] || b.count - a.count).slice(0, 20);

    const involved = new Set(findings.flatMap((f) => f.eventIds));
    const assembly = assemblyOf(events.filter((e) => involved.has(e.id)).slice(0, 50));
    const proposedActions = findings.filter((f) => RANK[f.riskLevel] >= RANK.high).slice(0, 10).map((f) => propose(assembly, {
      action: "rotate_credential", humanOnly: true, permission: null, destructive: false,
      description: `${f.label} seen ${f.count} time(s)${f.assets.length ? ` on ${f.assets.slice(0, 3).join(", ")}` : ""}. ${f.advice}`,
    }));
    return {
      window: { from, to },
      eventsAnalyzed: events.length,
      findings,
      overallRisk: findings.length ? findings.reduce((w, f) => (RANK[f.riskLevel] > RANK[w] ? f.riskLevel : w), "low" as z.infer<typeof riskLevel>) : "low",
      proposedActions,
      untrusted: ctx.untrusted(),
      limitations: [...secretExposureCheck.limitations],
    };
  },
};
