/**
 * PagerDuty — pages the on-call person (Events API v2). Outbound, notify only.
 * The integration (routing) key is sealed per connection. dedup_key is the Legion alert id, so PagerDuty itself
 * collapses repeats: a retry never pages twice. Only events.pagerduty.com is reachable.
 */
import { z } from "zod";
import { adapterFetch } from "./fetch.js";
import { severityAtLeast } from "./notify-filter.js";
import { PermanentDeliveryError, type OutboundAdapter } from "./types.js";

const KEY = /^[A-Za-z0-9]{32}$/;
const PD_SEVERITY = { critical: "critical", high: "error", medium: "warning", low: "info" } as const;

export const pagerdutyAdapter: OutboundAdapter = {
  manifest: {
    kind: "pagerduty", displayName: "PagerDuty", vendor: "PagerDuty", status: "available", plane: "tool", inbound: null, outbound: ["notify"],
    egressHosts: ["events.pagerduty.com"],
    summary: "Pages the on-call person for serious alerts (Events API v2). Repeats of one alert are collapsed by PagerDuty. Notifies only.",
    auth: "Events API v2 integration key (32 characters), sealed per connection.",
  },
  configSchema: z.strictObject({ min_severity: z.enum(["low", "medium", "high", "critical"]).default("critical") }),
  secretFields: ["routing_key"],
  validateSecrets: (s) => (KEY.test(s.routing_key ?? "") ? null : "routing_key: the 32-character Events API v2 integration key"),
  async deliver(conn, msg, signal) {
    if (!severityAtLeast(msg.severity, String(conn.config.min_severity ?? "critical"))) return {};
    if (!KEY.test(conn.secrets.routing_key ?? "")) throw new PermanentDeliveryError("The PagerDuty integration key is not valid");
    const res = await adapterFetch(pagerdutyAdapter.manifest, "https://events.pagerduty.com/v2/enqueue", {
      method: "POST", signal, timeoutMs: 15_000, maxBytes: 64 * 1024, headers: { "content-type": "application/json" },
      body: JSON.stringify({
        routing_key: conn.secrets.routing_key, event_action: "trigger", dedup_key: msg.alertId,
        payload: { summary: msg.title.slice(0, 1000), source: msg.target ?? "Legion", severity: PD_SEVERITY[msg.severity], custom_details: { summary: msg.summary.slice(0, 2000), source_ip: msg.sourceIp } },
        links: [{ href: msg.link, text: "Open in Legion" }],
      }),
    });
    if (res.status === 202 || res.status === 200) return {};
    if (res.status === 429 || res.status >= 500 || res.status === 408) throw new Error(`PagerDuty answered ${res.status}`);
    throw new PermanentDeliveryError(`PagerDuty refused the event (${res.status}); check the integration key`);
  },
};
