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
  if (!conns.rows.length) return 0;
  // Audit A-5: the number of queries is constant (3), however many connections the workspace has —
  // one read of the hourly counts for all of them, one multi-row insert.
  const counts = await client.query<{ recipient: string; n: number }>(
    `SELECT recipient, count(*)::int AS n FROM notification_outbox
      WHERE tenant_id = $1 AND kind = 'integration_message' AND recipient = ANY($2::text[]) AND created_at > now() - interval '1 hour'
      GROUP BY recipient`, [alert.tenant_id, conns.rows.map((c) => c.id)],
  );
  const recent = new Map(counts.rows.map((r) => [r.recipient, r.n]));
  const link = `${config.frontendUrl.replace(/\/$/, "")}/incident/${encodeURIComponent(alert.id)}`;
  const ids: string[] = [], dedupe: string[] = [], recipients: string[] = [], payloads: string[] = [];
  for (const c of conns.rows) {
    const adapter = outboundAdapter(c.kind);
    if (!adapter) continue;
    // A per-connection ceiling, like alert mail: a sensor controls how many alerts arrive, not how much a provider is called.
    if ((recent.get(c.id) ?? 0) >= config.alertEmailHourlyCap) continue;
    const message: OutboundMessage = {
      type: adapter.manifest.outbound.includes("ticket") ? "ticket" : "notify",
      alertId: alert.id, title: alert.title.slice(0, 300), severity: alert.severity, summary: (alert.summary ?? "").slice(0, 2000),
      sourceIp: alert.source_ip ?? null, target: alert.target ?? null, link,
    };
    ids.push(randomUUID()); dedupe.push(`${alert.id}:${c.id}`.slice(0, 200)); recipients.push(c.id); payloads.push(JSON.stringify(message));
  }
  if (!ids.length) return 0;
  const r = await client.query(
    `INSERT INTO notification_outbox (id, tenant_id, kind, dedupe_key, recipient, payload, max_attempts)
     SELECT i, $1, 'integration_message', d, rc, p::jsonb, $6 FROM unnest($2::uuid[], $3::text[], $4::text[], $5::text[]) AS t(i, d, rc, p)
     ON CONFLICT (tenant_id, kind, dedupe_key) DO NOTHING`,
    [alert.tenant_id, ids, dedupe, recipients, payloads, config.notifyMaxAttempts],
  );
  return r.rowCount ?? 0;
}

export interface AlertDelivery { connection: string; kind: string; status: string; ticket: { key: string; url: string } | null; last_error: string | null; sent_at: string | null }

/** Where one alert was sent (Slack, Jira…) and, for tickets, which ticket it became. Tenant-scoped. */
export async function deliveriesForAlert(tenantId: string, alertId: string): Promise<AlertDelivery[]> {
  const rows = await query<{ connection_id: string; name: string | null; kind: string | null; status: string; payload: { ticket?: { key?: unknown; url?: unknown } }; last_error: string | null; sent_at: string | null }>(
    `SELECT o.recipient AS connection_id, c.name, c.kind, o.status, o.payload, o.last_error, o.sent_at
       FROM notification_outbox o LEFT JOIN integration_connections c ON c.id::text = o.recipient AND c.tenant_id = o.tenant_id
      WHERE o.tenant_id = $1 AND o.kind = 'integration_message' AND o.payload->>'alertId' = $2
      ORDER BY o.created_at`, [tenantId, alertId],
  );
  const okUrl = (u: unknown): u is string => typeof u === "string" && /^https:\/\/[a-z0-9-]+\.atlassian\.net\/browse\//.test(u);
  const out: AlertDelivery[] = [];
  const seen = new Set<string>();
  for (const r of rows.rows) {
    seen.add(r.connection_id);
    const t = r.payload?.ticket;
    const ticket = t && typeof t.key === "string" && okUrl(t.url) ? { key: t.key, url: t.url } : null;
    out.push({ connection: r.name ?? "(removed)", kind: r.kind ?? "unknown", status: r.status, ticket, last_error: r.last_error, sent_at: r.sent_at ? new Date(r.sent_at).toISOString() : null });
  }
  // Audit A-7: tickets kept on the alert show even after the delivered outbox rows were pruned.
  const kept = await query<{ tickets: Array<{ connection_id?: unknown; key?: unknown; url?: unknown; at?: unknown }> }>("SELECT tickets FROM alerts WHERE tenant_id = $1 AND id = $2", [tenantId, alertId]);
  for (const t of kept.rows[0]?.tickets ?? []) {
    if (typeof t.connection_id !== "string" || seen.has(t.connection_id) || typeof t.key !== "string" || !okUrl(t.url)) continue;
    seen.add(t.connection_id);
    const c = await queryOne<{ name: string; kind: string }>("SELECT name, kind FROM integration_connections WHERE id::text = $1 AND tenant_id = $2", [t.connection_id, tenantId]);
    out.push({ connection: c?.name ?? "(removed)", kind: c?.kind ?? "jira", status: "sent", ticket: { key: t.key, url: t.url }, last_error: null, sent_at: typeof t.at === "string" ? t.at : null });
  }
  return out;
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
    // Audit A-6: what an attempt has done is written to the message at once, not only when it ends.
    const remember = async (patch: Record<string, unknown>) => { await query(`UPDATE notification_outbox SET payload = payload || $3::jsonb WHERE id = $1 AND tenant_id = $2`, [row.id, row.tenant_id, JSON.stringify(patch)]); };
    const result = await adapter.deliver({ id: conn.id, tenantId: conn.tenant_id, config: conn.config ?? {}, secrets }, row.payload as OutboundMessage, signal, remember);
    await query(
      `UPDATE integration_connections SET failures = 0, last_success_at = now(), last_error = NULL, updated_at = now() WHERE id = $1 AND tenant_id = $2`, [conn.id, conn.tenant_id],
    );
    if (result.ref) {
      // The ticket is remembered with the message, so the dashboard and an auditor can see which alert became which ticket.
      await query(`UPDATE notification_outbox SET payload = payload || $3::jsonb WHERE id = $1 AND tenant_id = $2`, [row.id, row.tenant_id, JSON.stringify({ ticket: result.ref })]);
      // Audit A-7: and on the alert itself (one entry per connection), because delivered rows are pruned after NOTIFY_RETENTION_DAYS.
      const alertId = (row.payload as { alertId?: unknown } | null)?.alertId;
      if (typeof alertId === "string") {
        const entry = JSON.stringify({ connection_id: conn.id, key: result.ref.key, url: result.ref.url, at: new Date().toISOString() });
        await query(
          `UPDATE alerts SET tickets = coalesce((SELECT jsonb_agg(t) FROM jsonb_array_elements(tickets) t WHERE t->>'connection_id' <> $3), '[]'::jsonb) || $4::jsonb
            WHERE tenant_id = $1 AND id = $2`, [conn.tenant_id, alertId, conn.id, `[${entry}]`],
        ).catch(() => { /* the outbox row still has it; the alert page falls back to that */ });
      }
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
