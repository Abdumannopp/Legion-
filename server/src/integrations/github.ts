/**
 * GitHub — secret scanning, code scanning and Dependabot alerts from a repository or organisation webhook.
 *
 * Authentication is GitHub's own scheme: X-Hub-Signature-256 = "sha256=" + HMAC-SHA256(secret, raw body), checked
 * in constant time on the raw bytes BEFORE parsing (route: POST /security-events/webhook/github?connection=<id>).
 * The secret belongs to one connection (sealed, never returned) and the connection decides the workspace, so
 * nothing in the request can choose it. This module only maps an authenticated event to a Finding.
 */
import { z } from "zod";
import { cleanText, parseTime, severityOf } from "./shared.js";
import type { Finding, NormalizeResult, PushAdapter } from "./types.js";

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => v !== null && typeof v === "object" && !Array.isArray(v);
const get = (o: unknown, path: string[]): unknown => path.reduce<unknown>((c, k) => (isObj(c) ? c[k] : undefined), o);

export const EVENTS = ["secret_scanning_alert", "code_scanning_alert", "dependabot_alert"] as const;

export interface GithubEvent { event: string; body: unknown }

function oneFinding(event: string, b: Obj): Finding | null {
  const action = cleanText(b.action, 40);
  // Only new or reopened alerts are findings; closing, fixing and dismissing are not.
  if (!["created", "reopened", "appeared_in_branch", "reintroduced"].includes(action)) return null;
  const alert = isObj(b.alert) ? b.alert : null;
  if (!alert) return null;
  const repo = cleanText(get(b, ["repository", "full_name"]), 200);
  const number = typeof alert.number === "number" ? alert.number : Number(alert.number);
  if (!Number.isFinite(number)) return null;
  const url = cleanText(alert.html_url, 300);
  const link = /^https:\/\/github\.com\//.test(url) ? url : "";
  const base = { occurredAt: parseTime(alert.created_at ?? alert.updated_at), sourceIp: null, target: repo || null, mitre: [] as string[], asset: null };
  if (event === "secret_scanning_alert") {
    // The secret itself is never read: only its kind and where it was found.
    const kind = cleanText(alert.secret_type_display_name ?? alert.secret_type, 120) || "secret";
    return { ...base, externalId: `ghss-${repo}-${number}`, title: cleanText(`Exposed secret in ${repo}: ${kind}`, 300), severity: "high",
      summary: `GitHub secret scanning found a ${kind} in ${repo}. Rotate it, then close the alert.${link ? `\n${link}` : ""}`, confidence: 85 };
  }
  if (event === "code_scanning_alert") {
    const rule = isObj(alert.rule) ? alert.rule : {};
    const level = cleanText(rule.security_severity_level ?? rule.severity, 20).toLowerCase();
    return { ...base, externalId: `ghcs-${repo}-${number}`, title: cleanText(`Code scanning in ${repo}: ${cleanText(rule.description ?? rule.id, 200)}`, 300),
      severity: severityOf(level === "error" ? "high" : level === "warning" ? "medium" : level === "note" ? "low" : level),
      summary: `${cleanText(get(alert, ["most_recent_instance", "message", "text"]), 500)}${link ? `\n${link}` : ""}`.trim() || cleanText(rule.description, 300), confidence: 70 };
  }
  if (event === "dependabot_alert") {
    const adv = isObj(alert.security_advisory) ? alert.security_advisory : {};
    const pkg = cleanText(get(alert, ["dependency", "package", "name"]), 100);
    return { ...base, externalId: `ghdb-${repo}-${number}`, title: cleanText(`Vulnerable dependency in ${repo}: ${pkg} — ${cleanText(adv.summary, 200)}`, 300),
      severity: severityOf(cleanText(adv.severity, 20).toLowerCase()),
      summary: `${cleanText(adv.summary, 500)}${adv.cve_id ? `\n${cleanText(adv.cve_id, 30)}` : ""}${link ? `\n${link}` : ""}`.trim(), confidence: 80 };
  }
  return null;
}

export const githubAdapter: PushAdapter & { configSchema: z.ZodType<Record<string, unknown>>; secretFields: string[] } = {
  manifest: {
    kind: "github", displayName: "GitHub", vendor: "GitHub", status: "available", plane: "data", inbound: "push", outbound: [], egressHosts: [],
    summary: "Secret scanning, code scanning and Dependabot alerts from a repository or organisation webhook (new and reopened alerts only).",
    auth: "Webhook secret of one connection; deliveries are verified with X-Hub-Signature-256 (HMAC-SHA256 of the raw body). POST /security-events/webhook/github?connection=<id>.",
  },
  configSchema: z.strictObject({}),
  secretFields: ["webhook_secret"],
  normalize(payload: unknown): NormalizeResult {
    const p = payload as Partial<GithubEvent> | null;
    if (!p || typeof p.event !== "string" || !isObj(p.body)) return { skipped: true, reason: "not a GitHub event" };
    if (!(EVENTS as readonly string[]).includes(p.event)) return { skipped: true, reason: "event type not used" };
    const f = oneFinding(p.event, p.body);
    return f ? { skipped: false, source: "github", findings: [f] } : { skipped: true, reason: "not a new alert" };
  },
};
