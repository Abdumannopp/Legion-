/**
 * Retention beyond alerts (plan-limits.ts handles alert history by plan).
 *
 *   payment checks     deleted after RETENTION_PAYMENT_MONTHS (24)
 *   workspace audit    after RETENTION_AUDIT_MONTHS (24) the email and IP address in
 *                      an entry are removed; the row stays, with only the anonymous
 *                      user id (a uuid that means nothing once the user row is gone)
 *
 * Hosted installations only: a self-hosted customer keeps their own data as long
 * as they choose. A workspace on a legal hold is skipped by every job.
 *
 * The audit log is append-only; these jobs are the deliberate, documented
 * erasure the database allows through its transaction-local switch.
 */
import { config } from "./config.js";
import { pool, query } from "./db/pool.js";

const EMAIL = "[[:alnum:]._%+-]+@[[:alnum:].-]+";

async function activeTenants(): Promise<string[]> {
  return (await query<{ id: string }>("SELECT id FROM tenants WHERE NOT legal_hold")).rows.map((r) => r.id);
}

export async function prunePaymentChecks(months = config.retentionPaymentMonths): Promise<number> {
  if (config.deploymentMode === "self-hosted" || !(months > 0)) return 0;
  let removed = 0;
  for (const tenantId of await activeTenants()) {
    const r = await query(
      "DELETE FROM payment_checks WHERE tenant_id = $1 AND created_at < now() - make_interval(months => $2)",
      [tenantId, Math.floor(months)],
    );
    removed += r.rowCount ?? 0;
  }
  return removed;
}

/** Removes the personal data (email, IP, and email addresses written into the detail text) from old audit entries. */
export async function pseudonymiseAudit(months = config.retentionAuditMonths): Promise<number> {
  if (config.deploymentMode === "self-hosted" || !(months > 0)) return 0;
  let changed = 0;
  for (const tenantId of await activeTenants()) {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query("SELECT set_config('legion.audit_erasure', 'on', true)");
      const r = await client.query(
        `UPDATE audit_log
            SET user_email = NULL, ip_address = NULL,
                detail = CASE WHEN detail IS NULL THEN NULL ELSE regexp_replace(detail, '${EMAIL}', '[removed]', 'g') END
          WHERE tenant_id = $1 AND created_at < now() - make_interval(months => $2)
            AND (user_email IS NOT NULL OR ip_address IS NOT NULL OR detail ~ '${EMAIL}')`,
        [tenantId, Math.floor(months)],
      );
      await client.query("COMMIT");
      changed += r.rowCount ?? 0;
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      throw error;
    } finally {
      client.release();
    }
  }
  return changed;
}

export async function runRetention(): Promise<{ payments: number; audit: number }> {
  return { payments: await prunePaymentChecks(), audit: await pseudonymiseAudit() };
}
