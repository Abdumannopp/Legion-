/**
 * Generic JSON webhook — a push integration for anything that can POST JSON.
 *
 * Also the way Elastic Security (Kibana alerting webhook / ECS documents) and
 * Splunk (webhook alert action) connect: their payloads are recognised by shape.
 * Authentication is the same per-credential HMAC as the Wazuh webhook, checked
 * on the raw bytes before this module sees anything.
 *
 * Body: one object, an array of objects, or {"events": [...]} — up to 200.
 * Recognised fields (first match wins) are listed in FIELD_NAMES; anything else
 * is ignored. An event with no usable title is skipped, never invented.
 */
import { clip } from "../ai-safety.js";
import { cleanText, MAX_EVENTS_PER_REQUEST, mitreIn, parseTime, pickIp, severityOf, sha } from "./shared.js";
import type { Finding, NormalizeResult, PushAdapter } from "./types.js";

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => v !== null && typeof v === "object" && !Array.isArray(v);
/** Reads "a.b.c" from nested objects, and also a literal flat key "a.b.c" (Kibana flattens). */
function get(o: Obj, path: string): unknown {
  if (path in o) return o[path];
  let cur: unknown = o;
  for (const part of path.split(".")) { if (!isObj(cur) || !(part in cur)) return undefined; cur = cur[part]; }
  return cur;
}
/** The first scalar (string/number/boolean) found at any of the paths; objects are skipped, so "host" can be a string or an ECS object. */
const first = (o: Obj, paths: string[]): unknown => {
  for (const p of paths) {
    let v = get(o, p);
    if (Array.isArray(v)) v = v[0];
    if (typeof v === "string" ? v !== "" : typeof v === "number" || typeof v === "boolean") return v;
  }
  return undefined;
};

const FIELD_NAMES = {
  title: ["title", "name", "alert_name", "rule.name", "kibana.alert.rule.name", "search_name", "message", "description", "event.action"],
  summary: ["summary", "description", "message", "kibana.alert.reason", "reason", "details", "result._raw", "event.original"],
  id: ["id", "event_id", "uuid", "alert_id", "_id", "kibana.alert.uuid", "event.id", "sid"],
  time: ["timestamp", "@timestamp", "time", "occurred_at", "event.created", "kibana.alert.start", "result._time", "_time"],
  ip: ["source_ip", "src_ip", "srcip", "source.ip", "client.ip", "client_ip", "src", "result.src_ip", "result.src", "result.clientip"],
  host: ["host", "hostname", "host.name", "target", "agent.name", "dest", "result.host", "result.dest"],
  severity: ["severity", "level", "priority", "event.severity", "kibana.alert.severity", "kibana.alert.risk_score", "rule.severity", "result.severity", "urgency"],
} as const;

function eventsOf(body: unknown): unknown[] {
  if (Array.isArray(body)) return body;
  if (isObj(body) && Array.isArray(body.events)) return body.events;
  if (isObj(body) && Array.isArray(body.alerts)) return body.alerts;
  return [body];
}

function oneFinding(raw: unknown): Finding | null {
  if (!isObj(raw)) return null;
  const title = cleanText(first(raw, [...FIELD_NAMES.title]), 300);
  if (!title) return null;
  const sevRaw = first(raw, [...FIELD_NAMES.severity]);
  // Elastic's risk_score and a bare number above 10 are 0–100; otherwise 0–10.
  const scale = typeof sevRaw === "number" && sevRaw > 10 ? "hundred" : "ten";
  const summary = cleanText(first(raw, [...FIELD_NAMES.summary]), 4000) || title;
  const hostRaw = cleanText(first(raw, [...FIELD_NAMES.host]), 255);
  const explicit = cleanText(first(raw, [...FIELD_NAMES.id]), 200);
  let canonical = "";
  try { canonical = JSON.stringify(raw); } catch { canonical = title; }
  const hostIp = pickIp(first(raw, ["host.ip", "agent.ip"]));
  return {
    externalId: explicit || `gen-${sha(canonical).slice(0, 40)}`,
    title,
    severity: severityOf(sevRaw, scale),
    summary: clip(summary, 4000),
    occurredAt: parseTime(first(raw, [...FIELD_NAMES.time])),
    sourceIp: pickIp(first(raw, [...FIELD_NAMES.ip])),
    target: hostRaw || null,
    mitre: mitreIn(first(raw, ["mitre", "mitre_technique", "threat.technique.id", "kibana.alert.rule.threat.technique.id"]), title, summary),
    confidence: 60,
    asset: hostRaw ? { name: hostRaw, ip: hostIp, os: cleanText(first(raw, ["host.os.name", "os"]), 100) || null } : null,
  };
}

export const genericWebhookAdapter: PushAdapter = {
  manifest: {
    kind: "generic_webhook", displayName: "Generic JSON webhook", vendor: "Any (Elastic Security, Splunk, custom)", status: "available", plane: "data",
    inbound: "push", outbound: [], egressHosts: [],
    summary: "Any system that can POST JSON signed with a Legion sensor credential: custom tools, Elastic Security alerts, Splunk webhook alert actions. Up to 200 events per request.",
    auth: "Per-credential HMAC-SHA256 over timestamp, nonce and raw body (Settings → Sensor credentials); replay-protected. POST /security-events/webhook/generic.",
  },
  normalize(body: unknown): NormalizeResult {
    const events = eventsOf(body);
    if (events.length > MAX_EVENTS_PER_REQUEST) return { skipped: true, reason: `more than ${MAX_EVENTS_PER_REQUEST} events in one request` };
    const findings: Finding[] = [];
    for (const e of events) { const f = oneFinding(e); if (f) findings.push(f); }
    if (!findings.length) return { skipped: true, reason: "no event with a title" };
    return { skipped: false, source: "generic_webhook", findings };
  },
};
