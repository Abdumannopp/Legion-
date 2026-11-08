/**
 * Microsoft Teams — alert notifications to a channel through a Teams Workflows (or legacy incoming) webhook URL.
 * The URL is the secret (it grants posting to one channel): sealed per connection, never returned or logged, and
 * accepted only on Microsoft's webhook hosts, so a connection cannot point Legion at an internal address.
 * Text from alerts is untrusted and sent as plain text in an Adaptive Card (no mentions, no markup).
 */
import { z } from "zod";
import { adapterFetch, hostAllowed } from "./fetch.js";
import { severityAtLeast } from "./notify-filter.js";
import { PermanentDeliveryError, type OutboundAdapter } from "./types.js";

const HOSTS = ["*.webhook.office.com", "*.logic.azure.com", "*.*.logic.azure.com", "*.powerplatform.com", "*.*.powerplatform.com", "*.*.*.powerplatform.com"];
const manifestHosts = { egressHosts: HOSTS };
function validUrl(raw: string): boolean {
  try { const u = new URL(raw); return u.protocol === "https:" && !u.username && !u.password && hostAllowed(manifestHosts, u.hostname); } catch { return false; }
}
const COLOR = { critical: "Attention", high: "Attention", medium: "Warning", low: "Default" } as const;

export const teamsAdapter: OutboundAdapter = {
  manifest: {
    kind: "teams", displayName: "Microsoft Teams", vendor: "Microsoft", status: "available", plane: "tool", inbound: null, outbound: ["notify"],
    egressHosts: HOSTS,
    summary: "Alert notifications to one Teams channel through a Workflows webhook, delivered through the notification outbox (retries, dead letters). Notifies only.",
    auth: "Teams Workflows / incoming-webhook URL, sealed per connection; never shown again after it is saved.",
  },
  configSchema: z.strictObject({ min_severity: z.enum(["low", "medium", "high", "critical"]).default("high") }),
  secretFields: ["webhook_url"],
  validateSecrets: (s) => (validUrl(s.webhook_url ?? "") ? null : "webhook_url: must be a Teams webhook URL (…webhook.office.com, …logic.azure.com or …powerplatform.com)"),
  async deliver(conn, msg, signal) {
    const url = conn.secrets.webhook_url ?? "";
    if (!validUrl(url)) throw new PermanentDeliveryError("The Teams webhook URL is not valid");
    if (!severityAtLeast(msg.severity, String(conn.config.min_severity ?? "high"))) return {};
    const facts = [...(msg.target ? [{ title: "Host", value: msg.target.slice(0, 100) }] : []), ...(msg.sourceIp ? [{ title: "Source address", value: msg.sourceIp }] : [])];
    const res = await adapterFetch(teamsAdapter.manifest, url, {
      method: "POST", signal, timeoutMs: 15_000, maxBytes: 64 * 1024, headers: { "content-type": "application/json" },
      body: JSON.stringify({
        type: "message",
        attachments: [{ contentType: "application/vnd.microsoft.card.adaptive", content: {
          $schema: "http://adaptivecards.io/schemas/adaptive-card.json", type: "AdaptiveCard", version: "1.4",
          body: [
            { type: "TextBlock", text: `${msg.severity.toUpperCase()}: ${msg.title.slice(0, 200)}`, weight: "Bolder", wrap: true, color: COLOR[msg.severity] },
            { type: "TextBlock", text: msg.summary.slice(0, 600), wrap: true },
            ...(facts.length ? [{ type: "FactSet", facts }] : []),
          ],
          actions: [{ type: "Action.OpenUrl", title: "Open in Legion", url: msg.link }],
        } }],
      }),
    });
    if (res.status >= 200 && res.status < 300) return {};
    if (res.status === 429 || res.status >= 500 || res.status === 408) throw new Error(`Teams answered ${res.status}`);
    throw new PermanentDeliveryError(`Teams refused the message (${res.status}); check the webhook`);
  },
};
