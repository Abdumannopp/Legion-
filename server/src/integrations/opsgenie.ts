/**
 * Opsgenie — alerts the on-call team (Alert API v2). Outbound, notify only.
 *
 * alias is "legion-<alert id>", so Opsgenie itself collapses repeats: a retry never pages twice. The API key of an
 * "API" integration (create alerts only) is sealed per connection and sent as "Authorization: GenieKey …". The
 * region is chosen from a fixed list (us → api.opsgenie.com, eu → api.eu.opsgenie.com). Legion creates alerts only.
 * Note: Atlassian has announced the end of Opsgenie as a separate product; Jira Service Management's alerting uses
 * the same API.
 */
import { z } from "zod";
import { adapterFetch } from "./fetch.js";
import { severityAtLeast } from "./notify-filter.js";
import { PermanentDeliveryError, type OutboundAdapter } from "./types.js";

const HOSTS = { us: "api.opsgenie.com", eu: "api.eu.opsgenie.com" } as const;
const PRIORITY = { critical: "P1", high: "P2", medium: "P3", low: "P4" } as const;
const KEY = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;

export const opsgenieAdapter: OutboundAdapter = {
  manifest: {
    kind: "opsgenie", displayName: "Opsgenie", vendor: "Atlassian", status: "available", plane: "tool", inbound: null, outbound: ["notify"],
    egressHosts: Object.values(HOSTS),
    summary: "Alerts the on-call team for serious alerts (Alert API v2). Repeats of one alert are collapsed by Opsgenie. Notifies only.",
    auth: "API key of an Opsgenie API integration (create alerts), sealed per connection.",
  },
  configSchema: z.strictObject({
    region: z.enum(["us", "eu"]).default("us"),
    min_severity: z.enum(["low", "medium", "high", "critical"]).default("high"),
  }),
  secretFields: ["api_key"],
  validateSecrets: (s) => (KEY.test(s.api_key ?? "") ? null : "api_key: the Opsgenie integration API key (a GUID)"),
  async deliver(conn, msg, signal) {
    if (!severityAtLeast(msg.severity, String(conn.config.min_severity ?? "high"))) return {};
    if (!KEY.test(conn.secrets.api_key ?? "")) throw new PermanentDeliveryError("The Opsgenie API key is not valid");
    const host = HOSTS[String(conn.config.region ?? "us") as keyof typeof HOSTS] ?? HOSTS.us;
    const res = await adapterFetch(opsgenieAdapter.manifest, `https://${host}/v2/alerts`, {
      method: "POST", signal, timeoutMs: 15_000, maxBytes: 64 * 1024,
      headers: { authorization: `GenieKey ${conn.secrets.api_key}`, "content-type": "application/json" },
      body: JSON.stringify({
        message: msg.title.slice(0, 130), alias: `legion-${msg.alertId}`.slice(0, 512),
        description: [msg.summary, msg.sourceIp ? `Source address: ${msg.sourceIp}` : "", `Open in Legion: ${msg.link}`].filter(Boolean).join("\n\n").slice(0, 15_000),
        priority: PRIORITY[msg.severity], source: "Legion", tags: ["legion", `severity-${msg.severity}`],
        entity: (msg.target ?? "").slice(0, 512) || undefined,
        details: { legion_alert: msg.alertId, link: msg.link },
      }),
    });
    if (res.status === 202 || res.status === 200) return {};
    if (res.status === 429 || res.status >= 500 || res.status === 408) throw new Error(`Opsgenie answered ${res.status}`);
    throw new PermanentDeliveryError(`Opsgenie refused the alert (${res.status}); check the API key and region`);
  },
};
