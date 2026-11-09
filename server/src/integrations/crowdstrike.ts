/**
 * CrowdStrike Falcon (EDR) — endpoint detections from the Alerts API v2 (pull, read only).
 *
 * API client with the single scope "Alerts: Read" (OAuth2 client credentials); the client secret is sealed per
 * connection. The cloud is chosen from a fixed list (us-1, us-2, eu-1, us-gov-1), never typed as a URL, so only
 * CrowdStrike's API hosts are reachable. Cursor: the newest updated_timestamp; the filter is ">=", so the boundary
 * alert comes again and is dropped as a duplicate — or, if CrowdStrike raised its severity, the Legion alert is
 * raised too (audit A-9). An alert is stored once, by its composite id. Legion never contains, isolates or changes
 * anything in Falcon.
 */
import { z } from "zod";
import { adapterFetch } from "./fetch.js";
import { cleanText, cursorSince, mitreIn, parseTime, pickIp, severityOf } from "./shared.js";
import type { Finding, PullAdapter } from "./types.js";

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => v !== null && typeof v === "object" && !Array.isArray(v);
const MAX_PAGES = 5;
const PAGE = 100;

export const CROWDSTRIKE_CLOUDS = {
  "us-1": "api.crowdstrike.com",
  "us-2": "api.us-2.crowdstrike.com",
  "eu-1": "api.eu-1.crowdstrike.com",
  "us-gov-1": "api.laggar.gcw.crowdstrike.com",
} as const;

export function findingFromFalcon(a: Obj): Finding | null {
  const id = cleanText(a.composite_id ?? a.id, 300);
  const name = cleanText(a.display_name ?? a.name, 250);
  if (!id || !name) return null;
  const device = isObj(a.device) ? a.device : {};
  const host = cleanText(device.hostname, 255);
  const user = cleanText(a.user_name, 120);
  const sevName = cleanText(a.severity_name, 30).toLowerCase();
  const severity = sevName ? severityOf(sevName === "informational" ? "low" : sevName) : severityOf(a.severity, "hundred");
  const tactic = cleanText(a.tactic, 80);
  const technique = cleanText(a.technique, 120);
  return {
    externalId: id,
    title: cleanText(`CrowdStrike: ${name}${host ? ` on ${host}` : ""}`, 300),
    severity,
    summary: [
      cleanText(a.description, 2000),
      tactic || technique ? `Tactic: ${tactic}${technique ? ` / ${technique}` : ""}` : "",
      a.filename ? `File: ${cleanText(a.filename, 255)}` : "",
      a.cmdline ? `Command line: ${cleanText(a.cmdline, 1000)}` : "",
      user ? `User: ${user}` : "",
      a.status ? `Falcon status: ${cleanText(a.status, 40)}` : "",
    ].filter(Boolean).join("\n") || name,
    occurredAt: parseTime(a.timestamp ?? a.created_timestamp),
    sourceIp: pickIp(device.external_ip, a.local_ip, device.local_ip),
    target: host || user || null,
    mitre: mitreIn(a.technique_id, a.tactic_id, a.description),
    confidence: typeof a.confidence === "number" && a.confidence >= 0 && a.confidence <= 100 ? a.confidence : 80,
    asset: host ? { name: host, ip: pickIp(device.local_ip), os: cleanText(device.platform_name ?? device.os_version, 60) || null } : null,
  };
}

export const crowdstrikeAdapter: PullAdapter = {
  manifest: {
    kind: "crowdstrike", displayName: "CrowdStrike Falcon (EDR)", vendor: "CrowdStrike", status: "available", plane: "data", inbound: "pull", outbound: [],
    egressHosts: Object.values(CROWDSTRIKE_CLOUDS),
    summary: "Falcon endpoint detections (malware, suspicious processes, hands-on-keyboard activity), polled by update time. Read only.",
    auth: "Falcon API client with the scope Alerts: Read only (client credentials); the client secret is sealed per connection.",
  },
  configSchema: z.strictObject({
    cloud: z.enum(Object.keys(CROWDSTRIKE_CLOUDS) as [keyof typeof CROWDSTRIKE_CLOUDS, ...(keyof typeof CROWDSTRIKE_CLOUDS)[]]).default("us-1"),
    client_id: z.string().regex(/^[a-f0-9]{32}$/i, "Falcon API client id (32 hex characters)"),
  }),
  secretFields: ["client_secret"],
  async poll(conn, cursor, signal) {
    const host = CROWDSTRIKE_CLOUDS[String(conn.config.cloud ?? "us-1") as keyof typeof CROWDSTRIKE_CLOUDS] ?? CROWDSTRIKE_CLOUDS["us-1"];
    const m = crowdstrikeAdapter.manifest;
    const tokenRes = await adapterFetch(m, `https://${host}/oauth2/token`, {
      method: "POST", signal, timeoutMs: 20_000, maxBytes: 64 * 1024, headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
      body: new URLSearchParams({ client_id: String(conn.config.client_id), client_secret: conn.secrets.client_secret ?? "" }).toString(),
    });
    if (tokenRes.status === 429 || tokenRes.status >= 500) throw new Error(`CrowdStrike sign-in answered ${tokenRes.status}; will retry`);
    if (tokenRes.status !== 201 && tokenRes.status !== 200) throw new Error(`CrowdStrike sign-in failed (${tokenRes.status}); check the cloud, client id and secret`);
    let token = "";
    try { token = String((JSON.parse(tokenRes.body) as { access_token?: unknown }).access_token ?? ""); } catch { /* below */ }
    if (!token) throw new Error("CrowdStrike sign-in returned no token");
    const auth = { authorization: `Bearer ${token}`, accept: "application/json" };

    const since = cursorSince(cursor);
    const findings: Finding[] = [];
    let newest = since;
    for (let page = 0; page < MAX_PAGES; page++) {
      const q = new URLSearchParams({ filter: `updated_timestamp:>='${since}'`, sort: "updated_timestamp.asc", limit: String(PAGE), offset: String(page * PAGE) });
      const ids = await adapterFetch(m, `https://${host}/alerts/queries/alerts/v2?${q}`, { method: "GET", signal, timeoutMs: 30_000, maxBytes: 2 * 1024 * 1024, headers: auth });
      if (ids.status === 429 || ids.status >= 500) throw new Error(`CrowdStrike answered ${ids.status}; will retry`);
      if (ids.status === 401 || ids.status === 403) throw new Error(`CrowdStrike refused the request (${ids.status}); the API client needs the scope Alerts: Read`);
      if (ids.status !== 200) throw new Error(`CrowdStrike answered ${ids.status}`);
      let list: string[] = [];
      try {
        const r = (JSON.parse(ids.body) as { resources?: unknown }).resources;
        list = (Array.isArray(r) ? r : []).filter((x): x is string => typeof x === "string" && x.length <= 300).slice(0, PAGE);
      } catch { throw new Error("CrowdStrike returned invalid JSON"); }
      if (!list.length) break;
      const got = await adapterFetch(m, `https://${host}/alerts/entities/alerts/v2`, {
        method: "POST", signal, timeoutMs: 30_000, maxBytes: 16 * 1024 * 1024, headers: { ...auth, "content-type": "application/json" }, body: JSON.stringify({ composite_ids: list }),
      });
      if (got.status === 429 || got.status >= 500) throw new Error(`CrowdStrike answered ${got.status}; will retry`);
      if (got.status !== 200) throw new Error(`CrowdStrike answered ${got.status} (alert details)`);
      let alerts: unknown[] = [];
      try { const r = (JSON.parse(got.body) as { resources?: unknown }).resources; alerts = Array.isArray(r) ? r : []; } catch { throw new Error("CrowdStrike returned invalid JSON"); }
      for (const a of alerts) {
        if (!isObj(a)) continue;
        const f = findingFromFalcon(a);
        if (f) findings.push(f);
        const u = parseTime(a.updated_timestamp);
        if (u && u > newest) newest = u;
      }
      if (list.length < PAGE) break;
    }
    return { findings, cursor: { since: newest } };
  },
};
