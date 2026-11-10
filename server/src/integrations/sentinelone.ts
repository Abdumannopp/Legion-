/**
 * SentinelOne Singularity (EDR) — threats from the Management API v2.1 (pull, read only).
 *
 * An API token of a user (or service user) with the "Viewer" role is enough; it is sealed per connection and sent
 * as "Authorization: ApiToken …". The console is chosen by name (acme → acme.sentinelone.net), never typed as a URL;
 * only *.sentinelone.net is reachable. Cursor: the newest updatedAt; the filter is "updatedAt__gte", so an updated
 * threat comes again — a duplicate, or a raised severity (audit A-9). A threat is stored once, by its id. Legion
 * never mitigates, quarantines or disconnects anything.
 *
 * SentinelOne threats have no severity field. Legion derives it: malicious and not mitigated → critical,
 * malicious → high, suspicious → medium, anything else → medium (never silently low).
 */
import { z } from "zod";
import { adapterFetch } from "./fetch.js";
import { cleanText, cursorSince, mitreIn, parseTime, pickIp } from "./shared.js";
import type { Finding, PullAdapter } from "./types.js";
import type { Severity } from "../types.js";

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => v !== null && typeof v === "object" && !Array.isArray(v);
const MAX_PAGES = 5;
const CONSOLE = /^[a-z0-9][a-z0-9-]{0,62}$/;

export function findingFromS1Threat(t: Obj): Finding | null {
  const id = cleanText(t.id, 64);
  const info = isObj(t.threatInfo) ? t.threatInfo : {};
  const name = cleanText(info.threatName, 250);
  if (!id || !name) return null;
  const agent = isObj(t.agentRealtimeInfo) ? t.agentRealtimeInfo : {};
  const detect = isObj(t.agentDetectionInfo) ? t.agentDetectionInfo : {};
  const host = cleanText(agent.agentComputerName ?? detect.agentComputerName, 255);
  const user = cleanText(detect.agentLastLoggedInUserName ?? info.processUser, 120);
  const level = String(info.confidenceLevel ?? "").toLowerCase();
  const mitigated = String(info.mitigationStatus ?? "").toLowerCase() === "mitigated";
  const severity: Severity = level === "malicious" ? (mitigated ? "high" : "critical") : level === "suspicious" ? "medium" : "medium";
  const techniques: string[] = [];
  for (const ind of Array.isArray(t.indicators) ? t.indicators : []) {
    if (!isObj(ind)) continue;
    for (const tac of Array.isArray(ind.tactics) ? ind.tactics : []) {
      if (!isObj(tac)) continue;
      for (const tech of Array.isArray(tac.techniques) ? tac.techniques : []) if (isObj(tech)) techniques.push(String(tech.name ?? ""), String(tech.link ?? ""));
    }
  }
  return {
    externalId: id,
    title: cleanText(`SentinelOne: ${name}${host ? ` on ${host}` : ""}`, 300),
    severity,
    summary: [
      `Verdict: ${cleanText(info.confidenceLevel, 30) || "unknown"}${info.classification ? ` (${cleanText(info.classification, 60)})` : ""}`,
      `Mitigation: ${cleanText(info.mitigationStatus, 40) || "unknown"}${info.incidentStatus ? `, incident ${cleanText(info.incidentStatus, 40)}` : ""}`,
      info.filePath ? `File: ${cleanText(info.filePath, 500)}` : "",
      info.sha1 ? `SHA-1: ${cleanText(info.sha1, 40)}` : "",
      user ? `User: ${user}` : "",
    ].filter(Boolean).join("\n"),
    occurredAt: parseTime(info.identifiedAt ?? info.createdAt),
    sourceIp: pickIp(detect.externalIp, detect.agentIpV4),
    target: host || user || null,
    mitre: mitreIn(techniques),
    confidence: level === "malicious" ? 90 : level === "suspicious" ? 60 : 50,
    asset: host ? { name: host, ip: pickIp(detect.agentIpV4), os: cleanText(agent.agentOsName ?? detect.agentOsName, 60) || null } : null,
  };
}

export const sentineloneAdapter: PullAdapter = {
  manifest: {
    kind: "sentinelone", displayName: "SentinelOne (EDR)", vendor: "SentinelOne", status: "available", plane: "data", inbound: "pull", outbound: [],
    egressHosts: ["*.sentinelone.net"],
    summary: "SentinelOne threats (malicious and suspicious detections on endpoints), polled by update time. Read only.",
    auth: "API token of a user or service user with the Viewer role; sealed per connection.",
  },
  configSchema: z.strictObject({ console: z.string().regex(CONSOLE, "Your console name: acme for acme.sentinelone.net") }),
  secretFields: ["api_token"],
  async poll(conn, cursor, signal) {
    const host = `${String(conn.config.console)}.sentinelone.net`;
    const since = cursorSince(cursor);
    const findings: Finding[] = [];
    let newest = since;
    let next = "";
    for (let page = 0; page < MAX_PAGES; page++) {
      const q = new URLSearchParams({ updatedAt__gte: since, sortBy: "updatedAt", sortOrder: "asc", limit: "100", ...(next ? { cursor: next } : {}) });
      const res = await adapterFetch(sentineloneAdapter.manifest, `https://${host}/web/api/v2.1/threats?${q}`, {
        method: "GET", signal, timeoutMs: 30_000, maxBytes: 16 * 1024 * 1024, headers: { authorization: `ApiToken ${conn.secrets.api_token ?? ""}`, accept: "application/json" },
      });
      if (res.status === 429 || res.status >= 500) throw new Error(`SentinelOne answered ${res.status}; will retry`);
      if (res.status === 401 || res.status === 403) throw new Error(`SentinelOne refused the token (${res.status}); check the API token and its role`);
      if (res.status !== 200) throw new Error(`SentinelOne answered ${res.status}`);
      let body: { data?: unknown; pagination?: { nextCursor?: unknown } } = {};
      try { body = JSON.parse(res.body); } catch { throw new Error("SentinelOne returned invalid JSON"); }
      for (const t of Array.isArray(body.data) ? body.data : []) {
        if (!isObj(t)) continue;
        const f = findingFromS1Threat(t);
        if (f) findings.push(f);
        const u = parseTime((isObj(t.threatInfo) ? t.threatInfo : {}).updatedAt);
        if (u && u > newest) newest = u;
      }
      next = typeof body.pagination?.nextCursor === "string" && body.pagination.nextCursor.length <= 2000 ? body.pagination.nextCursor : "";
      if (!next) break;
    }
    return { findings, cursor: { since: newest } };
  },
};
