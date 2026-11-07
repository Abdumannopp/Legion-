/**
 * Syslog / CEF — a push integration for text logs.
 *
 * Legion does not listen on a syslog port (UDP/514 or TCP/6514 would be an
 * unauthenticated network surface). Instead a collector the customer already
 * runs (rsyslog omhttp, Vector, Fluent Bit, Logstash, syslog-ng http()) POSTs the
 * lines — one event per line, text/plain — to POST /security-events/webhook/cef,
 * signed with a sensor credential. Up to 200 lines, 4 KB each.
 *
 * Understood: ArcSight CEF (with or without a syslog header). Other syslog lines
 * (RFC 3164 / 5424) are kept only when their syslog severity is "error" or worse
 * (0–3); routine lines are skipped, because every info line is not an alert.
 */
import { cleanText, MAX_EVENTS_PER_REQUEST, mitreIn, parseTime, pickIp, severityOf, sha } from "./shared.js";
import type { Finding, NormalizeResult, PushAdapter } from "./types.js";

const MAX_LINE = 4096;

/** Splits the CEF header on unescaped pipes: CEF:0|vendor|product|version|signature|name|severity|extension */
function splitHeader(s: string): string[] | null {
  const parts: string[] = [];
  let cur = "";
  for (let i = 0; i < s.length && parts.length < 7; i++) {
    const ch = s[i]!;
    if (ch === "\\" && i + 1 < s.length) { cur += s[i + 1]; i++; continue; }
    if (ch === "|") { parts.push(cur); cur = ""; continue; }
    cur += ch;
  }
  if (parts.length < 7) return null;
  parts.push(s.slice(indexAfterPipes(s, 7)));
  return parts;
}
function indexAfterPipes(s: string, n: number): number {
  let seen = 0;
  for (let i = 0; i < s.length; i++) {
    if (s[i] === "\\") { i++; continue; }
    if (s[i] === "|" && ++seen === n) return i + 1;
  }
  return s.length;
}

/** key=value pairs where a value may contain spaces and runs to the next " key=". */
export function parseExtension(ext: string): Record<string, string> {
  const out: Record<string, string> = {};
  const re = /(?:^|\s)([A-Za-z][A-Za-z0-9_.]{0,40})=/g;
  const marks: { key: string; start: number; valueAt: number }[] = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(ext)) !== null && marks.length < 100) marks.push({ key: m[1]!, start: m.index, valueAt: re.lastIndex });
  marks.forEach((k, i) => {
    const end = i + 1 < marks.length ? marks[i + 1]!.start : ext.length;
    out[k.key] = ext.slice(k.valueAt, end).trim().replace(/\\([=\\])/g, "$1").replace(/\\n/g, "\n").replace(/\\r/g, "\r");
  });
  return out;
}

function fromCef(line: string, at: number): Finding | null {
  const body = line.slice(at + 4); // after "CEF:"
  const h = splitHeader(body);
  if (!h) return null;
  const [, deviceVendor, deviceProduct, , signature, name, sevRaw, ext = ""] = h;
  const x = parseExtension(ext);
  const title = cleanText(name, 300) || cleanText(signature, 300);
  if (!title) return null;
  const host = cleanText(x.dhost || x.dvchost || x.shost || x.dst, 255);
  const parts = [x.msg, x.act ? `action=${x.act}` : "", x.outcome ? `outcome=${x.outcome}` : "", x.suser ? `user=${x.suser}` : "", x.duser ? `target user=${x.duser}` : "", x.request ? `request=${x.request}` : ""].filter(Boolean);
  const summary = cleanText(`${deviceVendor} ${deviceProduct}: ${parts.join("; ") || title}`, 4000);
  return {
    externalId: cleanText(x.externalId || x.eventId, 200) ? `cef-${cleanText(x.externalId || x.eventId, 200)}` : `cef-${sha(line).slice(0, 40)}`,
    title,
    severity: severityOf(sevRaw, "ten"),
    summary,
    occurredAt: parseTime(x.rt || x.end || x.start),
    sourceIp: pickIp(x.src, x.sourceAddress),
    target: host || null,
    mitre: mitreIn(ext, title),
    confidence: 60,
    asset: host ? { name: host, ip: pickIp(x.dst, x.dvc), os: null } : null,
  };
}

/** RFC 3164/5424: "<PRI>…". Only error-or-worse lines are findings. */
function fromSyslog(line: string): Finding | null {
  const m = /^<(\d{1,3})>(.*)$/s.exec(line);
  if (!m) return null;
  const pri = Number(m[1]);
  if (pri > 191) return null;
  const sev = pri & 7;
  if (sev > 3) return null;
  const rest = cleanText(m[2], 4000);
  if (!rest) return null;
  const sevName = (["emergency", "alert", "critical", "error"] as const)[sev]!;
  return {
    externalId: `syslog-${sha(line).slice(0, 40)}`,
    title: cleanText(`Syslog ${sevName}: ${rest}`, 300),
    severity: sev <= 1 ? "critical" : sev === 2 ? "high" : "medium",
    summary: rest,
    occurredAt: null,
    sourceIp: pickIp(/\b(?:\d{1,3}\.){3}\d{1,3}\b/.exec(rest)?.[0]),
    target: null,
    mitre: mitreIn(rest),
    confidence: 40,
    asset: null,
  };
}

export const cefAdapter: PushAdapter = {
  manifest: {
    kind: "cef", displayName: "Syslog / CEF", vendor: "Any (ArcSight CEF, rsyslog, syslog-ng, Vector, Fluent Bit, Logstash)", status: "available", plane: "data",
    inbound: "push", outbound: [], egressHosts: [],
    summary: "CEF events and error-level syslog lines forwarded over HTTPS by a collector you run; one event per line, up to 200 per request. Legion opens no syslog port.",
    auth: "Per-credential HMAC-SHA256 over timestamp, nonce and raw body (Settings → Sensor credentials); replay-protected. POST /security-events/webhook/cef with Content-Type text/plain.",
  },
  normalize(body: unknown): NormalizeResult {
    if (typeof body !== "string") return { skipped: true, reason: "expected text/plain lines" };
    const lines = body.split(/\r?\n/).filter((l) => l.trim());
    if (lines.length > MAX_EVENTS_PER_REQUEST) return { skipped: true, reason: `more than ${MAX_EVENTS_PER_REQUEST} lines in one request` };
    const findings: Finding[] = [];
    for (const raw of lines) {
      const line = raw.slice(0, MAX_LINE);
      const at = line.indexOf("CEF:");
      const f = at >= 0 && /^\d/.test(line.slice(at + 4)) ? fromCef(line, at) : fromSyslog(line);
      if (f) findings.push(f);
    }
    if (!findings.length) return { skipped: true, reason: "no CEF event or error-level syslog line" };
    return { skipped: false, source: "cef", findings };
  },
};
