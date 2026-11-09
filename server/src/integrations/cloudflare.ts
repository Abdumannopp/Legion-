/**
 * Cloudflare (WAF / edge) — addresses Cloudflare blocked or challenged on one zone, from the GraphQL Analytics API
 * (pull, read only).
 *
 * One alert per attacking address per UTC hour, not per request: a flood of blocked requests is one alert that
 * says how many, never thousands. An address appears only when it reached `min_events` blocked or challenged
 * requests in that hour. Hours are read once complete (the current hour is read in the next poll), at most 24 per
 * poll; the alert id is (zone, hour, address), so a re-read hour is a duplicate.
 *
 * An API token with the single permission "Zone · Analytics · Read" on that zone, sealed per connection. Only
 * api.cloudflare.com is reachable. Legion never changes firewall rules in Cloudflare.
 */
import { z } from "zod";
import { adapterFetch } from "./fetch.js";
import { cleanText, pickIp } from "./shared.js";
import type { Severity } from "../types.js";
import type { Finding, PullAdapter } from "./types.js";

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => v !== null && typeof v === "object" && !Array.isArray(v);
const HOUR = 3600_000;
const MAX_HOURS = 24;

const QUERY = `query LegionFirewall($zone: String!, $start: Time!, $end: Time!) {
  viewer { zones(filter: { zoneTag: $zone }) {
    firewallEventsAdaptiveGroups(limit: 100, orderBy: [count_DESC],
      filter: { datetime_geq: $start, datetime_lt: $end, action_in: ["block", "challenge", "managed_challenge", "jschallenge"] }) {
      count
      dimensions { clientIP clientCountryName clientRequestHTTPHost }
    }
  } }
}`;

const severityForCount = (n: number): Severity => (n >= 5000 ? "high" : n >= 500 ? "medium" : "low");

export function findingsFromCloudflare(zone: string, hourStart: string, groups: unknown[], minEvents: number): Finding[] {
  const out: Finding[] = [];
  // Several hosts of one zone give one group each: add them up per address.
  const byIp = new Map<string, { count: number; country: string; hosts: Set<string> }>();
  for (const g of groups) {
    if (!isObj(g) || !isObj(g.dimensions)) continue;
    const ip = pickIp(g.dimensions.clientIP);
    const count = typeof g.count === "number" && Number.isFinite(g.count) ? g.count : 0;
    if (!ip || count <= 0) continue;
    const e = byIp.get(ip) ?? { count: 0, country: cleanText(g.dimensions.clientCountryName, 4), hosts: new Set<string>() };
    e.count += count;
    const h = cleanText(g.dimensions.clientRequestHTTPHost, 255);
    if (h && e.hosts.size < 5) e.hosts.add(h);
    byIp.set(ip, e);
  }
  for (const [ip, e] of byIp) {
    if (e.count < minEvents) continue;
    const hosts = [...e.hosts];
    out.push({
      externalId: `${zone}:${hourStart}:${ip}`,
      title: cleanText(`Cloudflare blocked ${e.count} requests from ${ip}${hosts[0] ? ` to ${hosts[0]}` : ""}`, 300),
      severity: severityForCount(e.count),
      summary: [
        `${e.count} requests from ${ip} were blocked or challenged by Cloudflare in the hour from ${hourStart}.`,
        e.country ? `Country: ${e.country}` : "",
        hosts.length ? `Hosts: ${hosts.join(", ")}` : "",
        "Cloudflare already stopped these requests; the address may still be trying other ways in.",
      ].filter(Boolean).join("\n"),
      occurredAt: hourStart,
      sourceIp: ip,
      target: hosts[0] ?? null,
      mitre: ["T1190"],
      confidence: 60,
      asset: null,
    });
  }
  return out;
}

export const cloudflareAdapter: PullAdapter = {
  manifest: {
    kind: "cloudflare", displayName: "Cloudflare (WAF)", vendor: "Cloudflare", status: "available", plane: "data", inbound: "pull", outbound: [],
    egressHosts: ["api.cloudflare.com"],
    summary: "Addresses that Cloudflare's firewall blocked or challenged on one zone — one alert per address per hour, with the count. Read only.",
    auth: "API token with Zone · Analytics · Read on the zone, sealed per connection.",
  },
  configSchema: z.strictObject({
    zone_id: z.string().regex(/^[a-f0-9]{32}$/, "Zone id (32 hex characters, on the zone's Overview page)"),
    min_events: z.number().int().min(1).max(100_000).default(50),
  }),
  secretFields: ["api_token"],
  async poll(conn, cursor, signal) {
    const zone = String(conn.config.zone_id);
    const minEvents = Number(conn.config.min_events ?? 50);
    const lastFull = Math.floor(Date.now() / HOUR) * HOUR; // start of the current (incomplete) hour
    const c = (cursor as { next_hour?: unknown } | null)?.next_hour;
    let hour = typeof c === "number" && Number.isFinite(c) && c % HOUR === 0 && c <= lastFull ? c : lastFull - HOUR;
    hour = Math.max(hour, lastFull - MAX_HOURS * HOUR);
    const findings: Finding[] = [];
    for (; hour < lastFull; hour += HOUR) {
      const start = new Date(hour).toISOString();
      const end = new Date(hour + HOUR).toISOString();
      const res = await adapterFetch(cloudflareAdapter.manifest, "https://api.cloudflare.com/client/v4/graphql", {
        method: "POST", signal, timeoutMs: 30_000, maxBytes: 4 * 1024 * 1024,
        headers: { authorization: `Bearer ${conn.secrets.api_token ?? ""}`, "content-type": "application/json" },
        body: JSON.stringify({ query: QUERY, variables: { zone, start, end } }),
      });
      if (res.status === 429 || res.status >= 500) throw new Error(`Cloudflare answered ${res.status}; will retry`);
      if (res.status === 401 || res.status === 403) throw new Error(`Cloudflare refused the token (${res.status}); it needs Zone · Analytics · Read`);
      if (res.status !== 200) throw new Error(`Cloudflare answered ${res.status}`);
      let body: { data?: unknown; errors?: unknown } = {};
      try { body = JSON.parse(res.body); } catch { throw new Error("Cloudflare returned invalid JSON"); }
      if (Array.isArray(body.errors) && body.errors.length) {
        const msg = isObj(body.errors[0]) ? cleanText(body.errors[0].message, 200) : "query refused";
        throw new Error(`Cloudflare refused the query: ${msg}`);
      }
      const zones = isObj(body.data) && isObj(body.data.viewer) && Array.isArray(body.data.viewer.zones) ? body.data.viewer.zones : [];
      const groups = isObj(zones[0]) && Array.isArray(zones[0].firewallEventsAdaptiveGroups) ? zones[0].firewallEventsAdaptiveGroups : [];
      findings.push(...findingsFromCloudflare(zone, start, groups, minEvents));
    }
    return { findings, cursor: { next_hour: hour } };
  },
};
