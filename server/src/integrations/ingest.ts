/**
 * The one way findings enter Legion, whatever produced them.
 *
 * Each finding becomes an alert in ONE transaction with its asset, its email
 * and its realtime frame (outbox.insertAlertAndNotify). The alert id is
 * derived from (workspace, source, external id) with a keyed hash, so the
 * same finding sent twice — a sensor retrying, a poll re-run after a crash,
 * two instances racing — is one alert.
 */
import { createHmac } from "node:crypto";
import { clip } from "../ai-safety.js";
import { config } from "../config.js";
import * as outbox from "../outbox.js";
import type { Alert } from "../types.js";
import type { Finding } from "./types.js";

/** Unchanged from the original Wazuh webhook, so existing alert ids stay valid. */
export function findingAlertId(tenantId: string, source: string, externalId: string): string {
  return `SEC-${createHmac("sha256", config.webhookSecret || "legion-webhook-event-id").update(`${tenantId}:${source}:${externalId}`).digest("hex").slice(0, 16).toUpperCase()}`;
}

export interface IngestReport { ingested: string[]; duplicates: string[] }

export async function ingestFindings(
  tenantId: string, source: string, findings: Finding[], opts: { realtime?: (alert: Alert) => unknown } = {},
): Promise<IngestReport> {
  const report: IngestReport = { ingested: [], duplicates: [] };
  for (const f of findings) {
    const id = findingAlertId(tenantId, source, f.externalId);
    const alert = await outbox.insertAlertAndNotify({
      id, tenant_id: tenantId, title: clip(f.title, 300), severity: f.severity, agent: "Sentinel", status: "open",
      summary: f.summary.slice(0, 4000),
      confidence: Math.max(0, Math.min(100, Math.round(f.confidence))), ai_explanation: null, explained_at: null,
      source_ip: f.sourceIp, target: f.target ? clip(f.target, 255) : null,
      mitre_technique: f.mitre.length ? clip(f.mitre.join(", "), 200) || null : null,
      source: clip(source, 100),
      occurred_at: f.occurredAt,
    }, { asset: f.asset ?? null, realtime: opts.realtime });
    (alert ? report.ingested : report.duplicates).push(id);
  }
  return report;
}
