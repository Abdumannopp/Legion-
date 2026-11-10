/**
 * Slack — alert notifications to a channel, through a Slack incoming webhook.
 *
 * The webhook URL is the secret (it grants posting to one channel); it is sealed per connection, never
 * returned, never logged. The only host Legion will call is hooks.slack.com, and the URL must be a
 * hooks.slack.com/services/… path, so a connection cannot be pointed at an internal address.
 * Delivery goes through the notification outbox: retries with backoff, a dead letter after the last attempt.
 */
import { z } from "zod";
import { adapterFetch } from "./fetch.js";
import { severityAtLeast } from "./notify-filter.js";
import { PermanentDeliveryError, type OutboundAdapter } from "./types.js";

const HOOK = /^https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/_-]{8,200}$/;
const COLOR = { critical: "#b91c1c", high: "#c2410c", medium: "#a16207", low: "#475569" } as const;

/** Slack mrkdwn control characters in untrusted text are neutralised: no mentions, links or markup from an alert. */
const plain = (s: string, max: number) => s.replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" })[c]!).replace(/[*_~`]/g, "").slice(0, max);

export const slackAdapter: OutboundAdapter = {
  manifest: {
    kind: "slack", displayName: "Slack", vendor: "Salesforce", status: "available", plane: "tool", inbound: null, outbound: ["notify"],
    egressHosts: ["hooks.slack.com"],
    summary: "Alert notifications to one Slack channel, delivered through the notification outbox (retries, dead letters). Notifies only; changes nothing.",
    auth: "Slack incoming-webhook URL, sealed per connection; never shown again after it is saved.",
  },
  configSchema: z.strictObject({ min_severity: z.enum(["low", "medium", "high", "critical"]).default("high") }),
  secretFields: ["webhook_url"],
  validateSecrets: (s) => (HOOK.test(s.webhook_url ?? "") ? null : "webhook_url: must be a Slack incoming-webhook URL (https://hooks.slack.com/services/…)"),
  async deliver(conn, msg, signal) {
    const url = conn.secrets.webhook_url ?? "";
    if (!HOOK.test(url)) throw new PermanentDeliveryError("The Slack webhook URL is not valid");
    if (!severityAtLeast(msg.severity, String(conn.config.min_severity ?? "high"))) return {};
    const text = `*${msg.severity.toUpperCase()}* ${plain(msg.title, 200)}`;
    const res = await adapterFetch(slackAdapter.manifest, url, {
      method: "POST", signal, timeoutMs: 15_000, maxBytes: 64 * 1024,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        text,
        attachments: [{
          color: COLOR[msg.severity], text: plain(msg.summary, 600),
          fields: [
            ...(msg.target ? [{ title: "Host", value: plain(msg.target, 100), short: true }] : []),
            ...(msg.sourceIp ? [{ title: "Source address", value: plain(msg.sourceIp, 45), short: true }] : []),
          ],
          footer: `Legion · ${msg.alertId}`, title: "Open in Legion", title_link: msg.link,
        }],
      }),
    });
    if (res.status === 200) return {};
    // 429 and 5xx: the provider is busy or down — retry later. Other 4xx: the webhook is revoked or wrong — retrying cannot help.
    if (res.status === 429 || res.status >= 500 || res.status === 408) throw new Error(`Slack answered ${res.status}`);
    throw new PermanentDeliveryError(`Slack refused the message (${res.status}); check the webhook`);
  },
};
