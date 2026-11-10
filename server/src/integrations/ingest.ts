/**
 * The one way findings enter Legion, whatever produced them.
 *
 * Each finding becomes an alert in ONE transaction with its asset, its email
 * and its realtime frame (outbox.insertAlertAndNotify). The alert id is
 * derived from (workspace, source, external id) with a keyed hash, so the
 * same finding sent twice — a sensor retrying, a poll re-run after a crash,
 * two instances racing — is one alert.
 */
import { stripNul } from "../text.js";
import { createHmac } from "node:crypto";
import { clip } from "../ai-safety.js";
import { config } from "../config.js";
import * as outbox from "../outbox.js";
import { inTenant, queryOne, transaction } from "../db/pool.js";
import { enqueueIntegrationMessages } from "../integration-notify.js";
import * as store from "../store.js";
import { correlate } from "../campaigns.js";
import { respondToCampaigns } from "../blocklist.js";
import type { Alert } from "../types.js";
import type { Finding } from "./types.js";

/** Unchanged from the original Wazuh webhook, so existing alert ids stay valid. */
export function findingAlertId(tenantId: string, source: string, externalId: string): string {
  return `SEC-${createHmac("sha256", config.webhookSecret || "legion-webhook-event-id").update(`${tenantId}:${source}:${externalId}`).digest("hex").slice(0, 16).toUpperCase()}`;
}

/**
 * A sensor's text, made safe to store: no NUL characters (the database refuses
 * them, which would turn one odd event into a request that can never succeed).
 */
export function cleanFinding(f: Finding): Finding {
  return {
    ...f,
    externalId: stripNul(f.externalId),
    title: stripNul(f.title),
    summary: stripNul(f.summary),
    sourceIp: f.sourceIp === null ? null : stripNul(f.sourceIp),
    target: f.target === null ? null : stripNul(f.target),
    mitre: f.mitre.map(stripNul),
    asset: f.asset ? { name: stripNul(f.asset.name), ip: f.asset.ip === null ? null : stripNul(f.asset.ip), os: f.asset.os === null ? null : stripNul(f.asset.os) } : f.asset,
  };
}

export interface IngestReport { ingested: string[]; duplicates: string[]; campaigns?: string[]; /** Duplicates whose source raised the severity (audit A-9). */ escalated?: string[] }

const RANK = { low: 0, medium: 1, high: 2, critical: 3 } as const;

/**
 * Audit A-9: a vendor alert Legion already stored came again with a HIGHER severity (Defender, GuardDuty,
 * CrowdStrike… re-send an item when they update it). The Legion alert is raised to match, a dated note is
 * added to its text, and the change is audited. Severity is never lowered and status is never changed by a
 * source: closing or downgrading stays a person's decision. Outbound connections are told about the raise.
 */
async function escalateIfHigher(tenantId: string, id: string, f: Finding): Promise<boolean> {
  const row = await inTenant(tenantId, () => queryOne<{ severity: keyof typeof RANK }>(
    `UPDATE alerts SET severity = $3,
            summary = left(summary || E'\n\n' || $4, 4000)
      WHERE tenant_id = $1 AND id = $2
        AND (CASE severity WHEN 'low' THEN 0 WHEN 'medium' THEN 1 WHEN 'high' THEN 2 ELSE 3 END) < $5
      RETURNING severity`,
    [tenantId, id, f.severity, `[${new Date().toISOString()}] The source raised the severity to ${f.severity}.`, RANK[f.severity]],
  ));
  if (!row) return false;
  // Chat, paging and ticket connections hear of the raise: one whose threshold the alert did not reach before
  // (PagerDuty at "critical", the alert arrived as "medium") must not stay silent. Best effort, after the raise.
  await inTenant(tenantId, async () => {
    const alert = await store.getAlert(tenantId, id);
    if (alert) await transaction((client) => enqueueIntegrationMessages(client, alert, { raised: true }));
  }).then(() => outbox.kick()).catch((e) => console.error("Legion: could not queue the severity-raise notifications:", e instanceof Error ? e.message : "unknown error"));
  await store.audit({ tenant_id: tenantId, user_id: null, user_email: null, action: "alert.severity_raised_by_source", resource_type: "alert", resource_id: id, detail: `raised to ${f.severity} by the source`, ip_address: null }).catch(() => { /* the alert change stands; audit is best effort here */ });
  return true;
}

export async function ingestFindings(
  tenantId: string, source: string, findings: Finding[], opts: { realtime?: (alert: Alert) => unknown } = {},
): Promise<IngestReport> {
  const report: IngestReport = { ingested: [], duplicates: [] };
  const stored: Alert[] = [];
  for (const raw of findings) {
    const f = cleanFinding(raw);
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
    if (alert) stored.push(alert);
    else if (f.severity !== "low" && await escalateIfHigher(tenantId, id, f).catch(() => false)) (report.escalated ??= []).push(id);
  }
  // Campaign detection and the automatic response run AFTER the alerts are
  // committed, and never undo or fail ingestion: a sensor must not retry (and
  // spool) an event that was stored because correlation had a problem.
  if (stored.length) {
    try {
      const campaigns = await correlate(tenantId, stored, { realtime: opts.realtime });
      if (campaigns.length) {
        report.campaigns = campaigns.map((c) => c.id);
        await respondToCampaigns(tenantId, campaigns);
      }
    } catch (error) {
      console.error("Legion: campaign correlation failed:", error instanceof Error ? error.message : "unknown error");
    }
  }
  return report;
}
