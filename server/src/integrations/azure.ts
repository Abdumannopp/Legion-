/**
 * Microsoft Azure — Microsoft Defender for Cloud alerts per subscription (pull, read only).
 *
 * Entra ID app registration with the Reader role (or Security Reader) on the subscription; client credentials.
 * Hosts: login.microsoftonline.com and management.azure.com only (a paging link to any other host is refused).
 * The list API has no server-side time filter, so Legion keeps alerts newer than the cursor (timeGeneratedUtc);
 * an alert is stored once by its name (id).
 */
import { z } from "zod";
import { adapterFetch } from "./fetch.js";
import { cleanText, mitreIn, parseTime, pickIp, severityOf } from "./shared.js";
import type { ConnectionContext, Finding, IntegrationManifest, PullAdapter } from "./types.js";

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => v !== null && typeof v === "object" && !Array.isArray(v);
const MAX_PAGES = 10;

export function findingFromAzureAlert(a: Obj): Finding | null {
  const p = isObj(a.properties) ? a.properties : {};
  const id = cleanText(a.name, 200);
  const title = cleanText(p.alertDisplayName, 300);
  if (!id || !title) return null;
  let ip: string | null = null; let host: string | null = null; let account: string | null = null;
  for (const e of Array.isArray(p.entities) ? p.entities : []) {
    if (!isObj(e)) continue;
    const t = String(e.type ?? "").toLowerCase();
    if (!ip && t === "ip") ip = pickIp(e.address);
    if (!host && t === "host") host = cleanText(e.hostName ?? e.dnsDomain, 255) || null;
    if (!account && t === "account") account = cleanText(e.name, 120) || null;
  }
  const compromised = cleanText(p.compromisedEntity, 255);
  return {
    externalId: id,
    title,
    severity: severityOf(String(p.severity ?? "").toLowerCase() === "informational" ? "low" : p.severity),
    summary: [cleanText(p.description, 3000), account ? `Account: ${account}` : "", p.intent ? `Intent: ${cleanText(p.intent, 60)}` : "", p.productName ? `Source: ${cleanText(p.productName, 80)}` : "", p.status ? `Status: ${cleanText(p.status, 30)}` : ""].filter(Boolean).join("\n") || title,
    occurredAt: parseTime(p.timeGeneratedUtc),
    sourceIp: ip,
    target: host ?? (compromised || null) ?? account,
    mitre: mitreIn(p.techniques, p.description),
    confidence: 75,
    asset: host || compromised ? { name: (host ?? compromised)!, ip: null, os: null } : null,
  };
}

/** A management.azure.com token for the app registration of a connection (client credentials). Shared with Microsoft Sentinel. */
export async function azureManagementToken(manifest: Pick<IntegrationManifest, "egressHosts">, conn: ConnectionContext, signal: AbortSignal): Promise<string> {
  const tokenRes = await adapterFetch(manifest, `https://login.microsoftonline.com/${encodeURIComponent(String(conn.config.directory_id))}/oauth2/v2.0/token`, {
    method: "POST", signal, timeoutMs: 20_000, maxBytes: 64 * 1024, headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ client_id: String(conn.config.client_id), client_secret: conn.secrets.client_secret ?? "", scope: "https://management.azure.com/.default", grant_type: "client_credentials" }).toString(),
  });
  if (tokenRes.status !== 200) throw new Error(`Microsoft sign-in failed (${tokenRes.status}); check the directory id, application id and client secret`);
  let token = "";
  try { token = String((JSON.parse(tokenRes.body) as { access_token?: unknown }).access_token ?? ""); } catch { /* below */ }
  if (!token) throw new Error("Microsoft sign-in returned no token");
  return token;
}

export const azureAdapter: PullAdapter = {
  manifest: {
    kind: "azure", displayName: "Microsoft Azure (Defender for Cloud)", vendor: "Microsoft", status: "available", plane: "data", inbound: "pull", outbound: [],
    egressHosts: ["management.azure.com", "login.microsoftonline.com"],
    summary: "Microsoft Defender for Cloud security alerts of one subscription, polled by generation time. Read only.",
    auth: "Entra ID app registration (client credentials) with the Reader role on the subscription; the client secret is sealed per connection.",
  },
  configSchema: z.strictObject({
    directory_id: z.string().uuid("Directory (tenant) id, a GUID"),
    client_id: z.string().uuid("Application (client) id, a GUID"),
    subscription_id: z.string().uuid("Azure subscription id, a GUID"),
  }),
  secretFields: ["client_secret"],
  async poll(conn, cursor, signal) {
    const token = await azureManagementToken(azureAdapter.manifest, conn, signal);
    const since = typeof (cursor as { since?: unknown } | null)?.since === "string" ? (cursor as { since: string }).since : new Date(Date.now() - 24 * 3600_000).toISOString();
    let url: string | null = `https://management.azure.com/subscriptions/${encodeURIComponent(String(conn.config.subscription_id))}/providers/Microsoft.Security/alerts?api-version=2022-01-01`;
    const findings: Finding[] = [];
    let newest = since;
    for (let page = 0; url && page < MAX_PAGES; page++) {
      const res = await adapterFetch(azureAdapter.manifest, url, { method: "GET", signal, timeoutMs: 30_000, maxBytes: 8 * 1024 * 1024, headers: { authorization: `Bearer ${token}`, accept: "application/json" } });
      if (res.status === 429 || res.status >= 500) throw new Error(`Azure answered ${res.status}; will retry`);
      if (res.status !== 200) throw new Error(`Azure refused the request (${res.status}); check that the app has the Reader role on the subscription`);
      let body: { value?: unknown; nextLink?: unknown } = {};
      try { body = JSON.parse(res.body); } catch { throw new Error("Azure returned invalid JSON"); }
      for (const a of Array.isArray(body.value) ? body.value : []) {
        if (!isObj(a)) continue;
        const generated = parseTime((isObj(a.properties) ? a.properties : {}).timeGeneratedUtc);
        if (generated && generated < since) continue;
        const f = findingFromAzureAlert(a);
        if (f) findings.push(f);
        if (generated && generated > newest) newest = generated;
      }
      url = typeof body.nextLink === "string" ? body.nextLink : null;
    }
    return { findings, cursor: { since: newest } };
  },
};
