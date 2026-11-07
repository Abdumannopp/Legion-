/**
 * Microsoft Defender XDR (and Entra ID Protection, Purview alerts that Defender XDR aggregates) —
 * a pull integration over Microsoft Graph security alerts_v2.
 *
 * Authentication: an Entra app registration with the application permission SecurityAlert.Read.All
 * (client credentials). Legion asks login.microsoftonline.com for a token and then reads
 * graph.microsoft.com; no other host is reachable. The client secret is sealed per connection.
 * Read only: Legion never writes to the tenant.
 *
 * Cursor: the newest lastUpdateDateTime seen. The filter is "ge", so the boundary alert comes again and is
 * dropped as a duplicate (ingest is idempotent). An alert is stored once, by its id: later updates of the
 * same Microsoft alert do not create a second Legion alert.
 */
import { z } from "zod";
import { cleanText, mitreIn, parseTime, pickIp, severityOf } from "./shared.js";
import { adapterFetch } from "./fetch.js";
import type { Finding, PullAdapter } from "./types.js";

const GRAPH = "https://graph.microsoft.com/v1.0/security/alerts_v2";
const MAX_PAGES = 10;
const PAGE = 50;

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => v !== null && typeof v === "object" && !Array.isArray(v);
const str = (v: unknown, max: number) => cleanText(v, max);

export function findingFromAlert(a: Obj): Finding | null {
  const id = str(a.id, 200);
  const title = str(a.title, 300);
  if (!id || !title) return null;
  const evidence = Array.isArray(a.evidence) ? a.evidence.filter(isObj) : [];
  const kind = (e: Obj) => String(e["@odata.type"] ?? "").toLowerCase();
  let ip: string | null = null; let host: string | null = null; let account: string | null = null;
  for (const e of evidence) {
    if (!ip && kind(e).endsWith("ipevidence")) ip = pickIp(e.ipAddress);
    if (!host && kind(e).endsWith("deviceevidence")) host = str(e.deviceDnsName, 255) || null;
    if (!account && kind(e).endsWith("userevidence") && isObj(e.userAccount)) account = str(e.userAccount.accountName, 120) || null;
  }
  const desc = str(a.description, 3000);
  const parts = [desc, account ? `User: ${account}` : "", a.category ? `Category: ${str(a.category, 100)}` : "", a.serviceSource ? `Source: ${str(a.serviceSource, 60)}` : "", a.status ? `Status: ${str(a.status, 40)}` : ""].filter(Boolean);
  return {
    externalId: id,
    title,
    severity: severityOf(a.severity === "informational" ? "low" : a.severity),
    summary: parts.join("\n") || title,
    occurredAt: parseTime(a.createdDateTime),
    sourceIp: ip,
    target: host ?? account,
    mitre: mitreIn(Array.isArray(a.mitreTechniques) ? a.mitreTechniques : [], desc),
    confidence: 75,
    asset: host ? { name: host, ip: null, os: null } : null,
  };
}

export const m365Adapter: PullAdapter = {
  manifest: {
    kind: "m365", displayName: "Microsoft Defender XDR", vendor: "Microsoft", status: "available", plane: "data", inbound: "pull", outbound: [],
    egressHosts: ["graph.microsoft.com", "login.microsoftonline.com"],
    summary: "Microsoft Graph security alerts_v2 (Defender XDR, Entra ID Protection, Purview), polled by last update time. Read only.",
    auth: "Entra ID app registration, application permission SecurityAlert.Read.All (client credentials); the client secret is sealed per connection.",
  },
  configSchema: z.strictObject({
    directory_id: z.string().uuid("Directory (tenant) id, a GUID"),
    client_id: z.string().uuid("Application (client) id, a GUID"),
  }),
  secretFields: ["client_secret"],
  async poll(conn, cursor, signal) {
    const tokenRes = await adapterFetch(m365Adapter.manifest, `https://login.microsoftonline.com/${encodeURIComponent(String(conn.config.directory_id))}/oauth2/v2.0/token`, {
      method: "POST", signal, timeoutMs: 20_000, maxBytes: 64 * 1024,
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ client_id: String(conn.config.client_id), client_secret: conn.secrets.client_secret ?? "", scope: "https://graph.microsoft.com/.default", grant_type: "client_credentials" }).toString(),
    });
    if (tokenRes.status !== 200) throw new Error(`Microsoft sign-in failed (${tokenRes.status}); check the directory id, application id and client secret`);
    let token = "";
    try { token = String((JSON.parse(tokenRes.body) as { access_token?: unknown }).access_token ?? ""); } catch { /* below */ }
    if (!token) throw new Error("Microsoft sign-in returned no token");

    const since = typeof (cursor as { since?: unknown } | null)?.since === "string" ? (cursor as { since: string }).since : new Date(Date.now() - 24 * 3600_000).toISOString();
    const q = new URLSearchParams({ $filter: `lastUpdateDateTime ge ${since}`, $orderby: "lastUpdateDateTime asc", $top: String(PAGE) });
    let url: string | null = `${GRAPH}?${q}`;
    const findings: Finding[] = [];
    let newest = since;
    for (let page = 0; url && page < MAX_PAGES; page++) {
      const res = await adapterFetch(m365Adapter.manifest, url, { method: "GET", signal, timeoutMs: 30_000, maxBytes: 8 * 1024 * 1024, headers: { authorization: `Bearer ${token}`, accept: "application/json" } });
      if (res.status === 429 || res.status >= 500) throw new Error(`Microsoft Graph answered ${res.status}; will retry`);
      if (res.status !== 200) throw new Error(`Microsoft Graph refused the request (${res.status}); check that SecurityAlert.Read.All has admin consent`);
      let body: { value?: unknown; "@odata.nextLink"?: unknown } = {};
      try { body = JSON.parse(res.body); } catch { throw new Error("Microsoft Graph returned invalid JSON"); }
      for (const a of Array.isArray(body.value) ? body.value : []) {
        if (!isObj(a)) continue;
        const f = findingFromAlert(a);
        if (f) findings.push(f);
        const updated = parseTime(a.lastUpdateDateTime);
        if (updated && updated > newest) newest = updated;
      }
      const next = body["@odata.nextLink"];
      url = typeof next === "string" ? next : null;   // adapterFetch refuses any host but graph.microsoft.com
    }
    return { findings, cursor: { since: newest } };
  },
};
