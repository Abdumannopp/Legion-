/**
 * Microsoft Sentinel (SIEM) — open incidents of one Log Analytics workspace (pull, read only).
 *
 * The same kind of Entra ID app registration as the Azure connection (client credentials), with the role
 * "Microsoft Sentinel Reader" on the workspace. Hosts: login.microsoftonline.com and management.azure.com only.
 * Cursor: the newest lastModifiedTimeUtc; the filter is "ge", so an updated incident comes again — a duplicate, or
 * a raised severity (audit A-9). Closed incidents are skipped. An incident is stored once, by its name (a GUID).
 * Legion never changes, closes or assigns incidents in Sentinel.
 */
import { z } from "zod";
import { adapterFetch } from "./fetch.js";
import { azureManagementToken } from "./azure.js";
import { cleanText, cursorSince, mitreIn, parseTime, severityOf } from "./shared.js";
import type { Finding, PullAdapter } from "./types.js";

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => v !== null && typeof v === "object" && !Array.isArray(v);
const MAX_PAGES = 10;
const NAME = /^[A-Za-z0-9._()-]{1,90}$/;

export function findingFromSentinelIncident(i: Obj): Finding | null {
  const p = isObj(i.properties) ? i.properties : {};
  const id = cleanText(i.name, 100);
  const title = cleanText(p.title, 250);
  if (!id || !title) return null;
  if (String(p.status ?? "").toLowerCase() === "closed") return null;
  const extra = isObj(p.additionalData) ? p.additionalData : {};
  const products = Array.isArray(extra.alertProductNames) ? extra.alertProductNames.map((x) => cleanText(x, 60)).filter(Boolean).slice(0, 5) : [];
  const tactics = Array.isArray(extra.tactics) ? extra.tactics.map((x) => cleanText(x, 40)).filter(Boolean).slice(0, 10) : [];
  return {
    externalId: id,
    title: cleanText(`Sentinel incident${p.incidentNumber ? ` #${cleanText(p.incidentNumber, 12)}` : ""}: ${title}`, 300),
    severity: severityOf(String(p.severity ?? "").toLowerCase() === "informational" ? "low" : p.severity),
    summary: [
      cleanText(p.description, 3000),
      typeof extra.alertsCount === "number" ? `Alerts in the incident: ${extra.alertsCount}` : "",
      products.length ? `Sources: ${products.join(", ")}` : "",
      tactics.length ? `Tactics: ${tactics.join(", ")}` : "",
      p.status ? `Sentinel status: ${cleanText(p.status, 20)}` : "",
    ].filter(Boolean).join("\n") || title,
    occurredAt: parseTime(p.firstActivityTimeUtc ?? p.createdTimeUtc),
    sourceIp: null,
    target: null,
    mitre: mitreIn(extra.techniques, p.description),
    confidence: 75,
    asset: null,
  };
}

export const msentinelAdapter: PullAdapter = {
  manifest: {
    kind: "msentinel", displayName: "Microsoft Sentinel (SIEM)", vendor: "Microsoft", status: "available", plane: "data", inbound: "pull", outbound: [],
    egressHosts: ["management.azure.com", "login.microsoftonline.com"],
    summary: "Open Microsoft Sentinel incidents of one workspace, polled by last change. Read only.",
    auth: "Entra ID app registration (client credentials) with Microsoft Sentinel Reader on the workspace; the client secret is sealed per connection.",
  },
  configSchema: z.strictObject({
    directory_id: z.string().uuid("Directory (tenant) id, a GUID"),
    client_id: z.string().uuid("Application (client) id, a GUID"),
    subscription_id: z.string().uuid("Azure subscription id, a GUID"),
    resource_group: z.string().regex(NAME, "Resource group name"),
    workspace: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9-]{2,62}$/, "Log Analytics workspace name"),
  }),
  secretFields: ["client_secret"],
  async poll(conn, cursor, signal) {
    const token = await azureManagementToken(msentinelAdapter.manifest, conn, signal);
    const since = cursorSince(cursor);
    const c = conn.config;
    const base = `https://management.azure.com/subscriptions/${encodeURIComponent(String(c.subscription_id))}/resourceGroups/${encodeURIComponent(String(c.resource_group))}` +
      `/providers/Microsoft.OperationalInsights/workspaces/${encodeURIComponent(String(c.workspace))}/providers/Microsoft.SecurityInsights/incidents`;
    const q = new URLSearchParams({ "api-version": "2023-02-01", $filter: `properties/lastModifiedTimeUtc ge ${since}`, $orderby: "properties/lastModifiedTimeUtc asc", $top: "50" });
    let url: string | null = `${base}?${q}`;
    const findings: Finding[] = [];
    let newest = since;
    for (let page = 0; url && page < MAX_PAGES; page++) {
      const res = await adapterFetch(msentinelAdapter.manifest, url, { method: "GET", signal, timeoutMs: 30_000, maxBytes: 8 * 1024 * 1024, headers: { authorization: `Bearer ${token}`, accept: "application/json" } });
      if (res.status === 429 || res.status >= 500) throw new Error(`Microsoft Sentinel answered ${res.status}; will retry`);
      if (res.status === 404) throw new Error("Microsoft Sentinel workspace not found; check the subscription, resource group and workspace name");
      if (res.status !== 200) throw new Error(`Microsoft Sentinel refused the request (${res.status}); the app needs Microsoft Sentinel Reader on the workspace`);
      let body: { value?: unknown; nextLink?: unknown } = {};
      try { body = JSON.parse(res.body); } catch { throw new Error("Microsoft Sentinel returned invalid JSON"); }
      for (const i of Array.isArray(body.value) ? body.value : []) {
        if (!isObj(i)) continue;
        const f = findingFromSentinelIncident(i);
        if (f) findings.push(f);
        const t = parseTime((isObj(i.properties) ? i.properties : {}).lastModifiedTimeUtc);
        if (t && t > newest) newest = t;
      }
      url = typeof body.nextLink === "string" ? body.nextLink : null;
    }
    return { findings, cursor: { since: newest } };
  },
};
