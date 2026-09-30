/**
 * Wazuh (and anything that sends the same shape) — a push integration.
 *
 * Authentication stays where it was: the per-credential HMAC scheme of
 * webhook-auth.ts / webhook-credentials.ts, checked on the raw bytes before
 * anything is parsed. This module only maps an authenticated Wazuh alert to a
 * Finding. The mapping is the one Legion has always used, and the external id
 * is the same, so alert ids are unchanged by the move (no duplicates on upgrade).
 */
import { clip, isIp } from "../ai-safety.js";
import type { Severity } from "../types.js";
import type { NormalizeResult, PushAdapter } from "./types.js";

/**
 * The sensor's own time for an event (Wazuh: "2026-09-30T01:02:03.456+0000"),
 * or null. Kept apart from created_at (when Legion stored it) because they
 * differ when a sensor re-sends from its spool after an outage — an analyst
 * needs to know an alert that arrived now happened an hour ago. Anything
 * unparseable, before 2000 or more than five minutes in the future (a wrong
 * sensor clock) is ignored rather than trusted.
 */
export function eventTime(raw: unknown): string | null {
  if (typeof raw !== "string" || raw.length > 64) return null;
  const normalised = raw.trim().replace(/([+-]\d{2})(\d{2})$/, "$1:$2");
  const t = Date.parse(normalised);
  if (!Number.isFinite(t) || t < Date.UTC(2000, 0, 1) || t > Date.now() + 5 * 60_000) return null;
  return new Date(t).toISOString();
}

export const wazuhAdapter: PushAdapter = {
  manifest: {
    kind: "wazuh", displayName: "Wazuh", vendor: "Wazuh", status: "available", plane: "data",
    inbound: "push", outbound: [], egressHosts: [],
    summary: "Alerts from Wazuh managers (and compatible senders) through the Legion integration script, with an on-disk spool for outages.",
    auth: "Per-credential HMAC-SHA256 over timestamp, nonce and raw body (Settings → Sensor credentials); replay-protected.",
  },
  normalize(body: unknown): NormalizeResult {
    const b = (body !== null && typeof body === "object" ? body : {}) as { event?: unknown; provider?: unknown } & Record<string, unknown>;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const event: any = b.event || b;
    const description = String(event?.rule?.description || "");
    if (!description) return { skipped: true, reason: "no rule description" };
    const level = Number(event.rule?.level || 0);
    // Whatever the sensor sends is bounded and shaped before it is stored: these
    // fields feed prompts and analyst-facing suggestions, and are attacker-
    // influenced. (The original text remains in the summary/full_log.)
    const srcip = typeof event.data?.srcip === "string" && isIp(event.data.srcip) ? event.data.srcip : null;
    const severity: Severity = level >= 12 ? "critical" : level >= 9 ? "high" : level >= 5 ? "medium" : "low";
    const agentName = event.agent?.name ? clip(String(event.agent.name), 255) : null;
    const mitre = Array.isArray(event.rule?.mitre?.id) ? clip(event.rule.mitre.id.map(String).join(", "), 200) : "";
    return {
      skipped: false,
      source: String(b.provider || "webhook"),
      findings: [{
        externalId: String(event.id || JSON.stringify(event)),
        title: clip(description, 300),
        severity,
        summary: String(event.full_log || description).slice(0, 4000),
        occurredAt: eventTime(event.timestamp),
        sourceIp: srcip,
        target: agentName,
        mitre: mitre ? [mitre] : [],
        confidence: Math.min(100, level * 7),
        // Turns the asset inventory into live data from the sensors.
        asset: agentName ? {
          name: agentName,
          ip: event.agent?.ip ? String(event.agent.ip) : null,
          os: event.agent?.os?.name ? String(event.agent.os.name) : null,
        } : null,
      }],
    };
  },
};
