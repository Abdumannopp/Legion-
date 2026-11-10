/**
 * Tells a workspace's administrators what Legion did on its own, or what it is waiting for a person to
 * decide. Queued in the SAME transaction as the state change (the outbox, outbox.ts), so a notice exists
 * if and only if the change committed; the worker sends it with the usual retries. Without SMTP nothing
 * is queued — the dashboard and the audit trail still show everything.
 */
import { randomUUID } from "node:crypto";
import type { PoolClient } from "pg";
import { config } from "./config.js";
import { isLocale } from "./i18n.js";
import { mailEnabled, protectionEmail } from "./mailer.js";

export interface ProtectionNotice {
  kind: "acted" | "failed" | "approval" | "notice";
  title: string;
  facts: Array<[string, string]>;
  /** Dashboard path the mail links to. */
  path: string;
}

/** Returns how many mails were queued. `dedupe` makes a repeat (a retry, a replay) queue nothing new. */
export async function enqueueProtectionNotice(client: PoolClient, tenantId: string, dedupe: string, notice: ProtectionNotice): Promise<number> {
  if (!mailEnabled()) return 0;
  const sent = await client.query<{ n: number }>(
    "SELECT count(*)::int AS n FROM notification_outbox WHERE tenant_id = $1 AND kind = 'protection_email' AND created_at > now() - interval '1 hour'", [tenantId],
  );
  if ((sent.rows[0]?.n ?? 0) >= config.alertEmailHourlyCap) return 0;   // the cap alert mail has too; the dashboard still shows it
  const t = await client.query<{ notification_email: string | null; notification_locale: string | null }>(
    "SELECT notification_email, notification_locale FROM tenants WHERE id = $1", [tenantId],
  );
  const admins = await client.query<{ email: string }>(
    `SELECT u.email FROM workspace_memberships m JOIN users u ON u.id = m.user_id
      WHERE m.tenant_id = $1 AND m.role = 'admin' AND m.status = 'active' AND u.status = 'active' AND u.email_verified_at IS NOT NULL`, [tenantId],
  );
  const recipients = new Map<string, string>();
  for (const e of [t.rows[0]?.notification_email, ...admins.rows.map((r) => r.email)]) {
    if (e && !recipients.has(e.toLowerCase())) recipients.set(e.toLowerCase(), e);
  }
  const locale = isLocale(t.rows[0]?.notification_locale) ? t.rows[0]!.notification_locale! : "en";
  const payload = JSON.stringify(protectionEmail({ ...notice, locale }));
  let queued = 0;
  for (const [key, address] of recipients) {
    const r = await client.query(
      `INSERT INTO notification_outbox (id, tenant_id, kind, dedupe_key, recipient, payload, max_attempts)
       VALUES ($1, $2, 'protection_email', $3, $4, $5, $6)
       ON CONFLICT (tenant_id, kind, dedupe_key) DO NOTHING`,
      [randomUUID(), tenantId, `${dedupe}:${key}`.slice(0, 200), address, payload, config.notifyMaxAttempts],
    );
    queued += r.rowCount ?? 0;
  }
  return queued;
}
