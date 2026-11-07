/**
 * Alerts into chat and ticket systems (Slack, Jira, …): the glue between ingestion and the outbound adapters.
 *
 * enqueueIntegrationMessages runs in the SAME transaction as the alert (outbox.insertAlertAndNotify), so a
 * message exists if and only if the alert committed; one row per (alert, connection) makes a replay a no-op.
 * deliverIntegrationMessage runs in the outbox worker: it opens the connection's sealed secrets, calls the
 * adapter with a timeout, records the connection's health, and reports the outcome to the outbox, which
 * retries with backoff when the provider is down. Nothing here can change anything in the customer's
 * environment: outbound adapters only notify or open tickets.
 */
import { randomUUID } from "node:crypto";
import type { PoolClient } from "pg";
import { config } from "./config.js";
import { query, queryOne } from "./db/pool.js";
import * as box from "./secret-box.js";
import { outboundAdapter, outboundKinds } from "./integrations/registry.js";
import { PermanentDeliveryError, type OutboundMessage } from "./integrations/types.js";
import type { Alert } from "./types.js";

const FAILURES_BEFORE_ERROR = 10;
const sealContext = (id: string, tenantId: string) => `integration:${tenantId}:${id}`;

export interface QueuedIntegrationMessage extends OutboundMessage { connectionId: string }

/** In the caller's transaction: queue one message per active outbound connection of the alert's workspace. */
export async function enqueueIntegrationMessages(client: PoolClient, alert: Alert): Promise<number> {
  const kinds = outboundKinds();
  if (!kinds.length) return 0;
  const conns = await client.query<{ id: string; kind: string; config: { min_severity?: string } | null }>(
    "SELECT id, kind, config FROM integration_connections WHERE tenant_id = $1 AND status = 'active' AND kind = ANY($2::text[])", [alert.tenant_id, kinds],
  );
  let queued = 0;
  for (const c of conns.rows) {
    const adapter = outboundAdapter(c.kind);
    if (!adapter) continue;
    // A per-connection ceiling, like alert mail: a sensor controls how many alerts arrive, not how much a provider is called.
    const recent = await client.query<{ n: number }>(
      "SELECT count(*)::int AS n FROM notification_outbox WHERE tenant_id = $1 AND kind = 'integration_message' AND recipient = $2 AND created_at > now() - interval '1 hour'", [alert.tenant_id, c.id],
    );
    if ((recent.rows[0]?.n ?? 0) >= config.alertEmailHourlyCap) continue;
    const message: OutboundMessage = {
      type: adapter.manifest.outbound.includes("ticket") ? "ticket" : "notify",
      alertId: alert.id, title: alert.title.slice(0, 300), severity: alert.severity, summary: (alert.summary ?? "").slice(0, 2000),
      sourceIp: alert.source_ip ?? null, target: alert.target ?? null,
      link: `${config.frontendUrl.replace(/\/$/, "")}/alerts/${encodeURIComponent(alert.id)}`,
    };
    const r = await client.query(
      `INSERT INTO notification_outbox (id, tenant_id, kind, dedupe_key, recipient, payload, max_attempts)
       VALUES ($1, $2, 'integration_message', $3, $4, $5, $6) ON CONFLICT (tenant_id, kind, dedupe_key) DO NOTHING`,
      [randomUUID(), alert.tenant_id, `${alert.id}:${c.id}`.slice(0, 200), c.id, JSON.stringify(message), config.notifyMaxAttempts],
    );
    queued += r.rowCount ?? 0;
  }
  return queued;
}

export type DeliveryOutcome = { ok: true } | { ok: false; detail: string; permanent?: boolean };

/** What an error may say about a credential: nothing. Any stored secret value found in it is removed. */
function scrub(text: string, secrets: Record<string, string>): string {
  let s = text;
  for (const v of Object.values(secrets)) if (v && v.length >= 6) s = s.split(v).join("[redacted]");
  return s.replace(/https:\/\/hooks\.slack\.com\/\S+/g, "[redacted-url]").replace(/\b(?:Bearer|Basic)\s+\S+/gi, "[redacted]").replace(/\s+/g, " ").slice(0, 300);
}

export async function deliverIntegrationMessage(row: { id: string; tenant_id: string; recipient: string; payload: unknown }, signal: AbortSignal): Promise<DeliveryOutcome> {
  const conn = await queryOne<{ id: string; tenant_id: string; kind: string; status: string; config: Record<string, unknown> | null; secrets_enc: string | null }>(
    "SELECT id, tenant_id, kind, status, config, secrets_enc FROM integration_connections WHERE id = $1 AND tenant_id = $2", [row.recipient, row.tenant_id],
  );
  // Removed (disabled) or gone: the customer chose to stop; nothing to deliver and nothing to retry.
  if (!conn || conn.status === "disabled") return { ok: true };
  // Paused or in error: keep the message and try again later (the retry budget bounds it).
  if (conn.status !== "active") return { ok: false, detail: `connection is ${conn.status}` };
  const adapter = outboundAdapter(conn.kind);
  if (!adapter) return { ok: false, detail: "integration no longer available", permanent: true };
  let secrets: Record<string, string> = {};
  try {
    const opened = conn.secrets_enc ? box.open(conn.secrets_enc, "integration-secret", sealContext(conn.id, conn.tenant_id)) : "{}";
    if (opened === null) throw new Error("stored credentials cannot be decrypted with the current keyring");
    secrets = JSON.parse(opened) as Record<string, string>;
    const result = await adapter.deliver({ id: conn.id, tenantId: conn.tenant_id, config: conn.config ?? {}, secrets }, row.payload as OutboundMessage, signal);
    await query(
      `UPDATE integration_connections SET failures = 0, last_success_at = now(), last_error = NULL, updated_at = now() WHERE id = $1 AND tenant_id = $2`, [conn.id, conn.tenant_id],
    );
    if (result.ref) {
      // The ticket is remembered with the message, so the dashboard and an auditor can see which alert became which ticket.
      await query(`UPDATE notification_outbox SET payload = payload || $3::jsonb WHERE id = $1 AND tenant_id = $2`, [row.id, row.tenant_id, JSON.stringify({ ticket: result.ref })]);
    }
    return { ok: true };
  } catch (error) {
    const detail = scrub(error instanceof Error ? error.message : "delivery failed", secrets);
    await query(
      `UPDATE integration_connections SET failures = failures + 1, last_error = $3, updated_at = now(),
              status = CASE WHEN failures + 1 >= $4 THEN 'error' ELSE status END
        WHERE id = $1 AND tenant_id = $2`, [conn.id, conn.tenant_id, detail, FAILURES_BEFORE_ERROR],
    ).catch(() => { /* health is best effort; the outbox records the failure too */ });
    return { ok: false, detail, permanent: error instanceof PermanentDeliveryError };
  }
}
