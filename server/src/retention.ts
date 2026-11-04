/**
 * Retention beyond alerts (plan-limits.ts handles alert history by plan).
 *
 *   payment checks     deleted after RETENTION_PAYMENT_MONTHS (24)
 *   agent logs         the oldest rows of the hash-chained agent logs (identity audit,
 *                      firewall decisions, content scans, tool calls) are deleted after
 *                      RETENTION_AGENT_LOG_MONTHS (24); see pruneAgentLogs
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

/**
 * The agent logs are hash-chained and cannot be edited, so their personal data
 * (addresses, user agents, previews of what an agent read or sent) goes by
 * deleting the OLDEST rows of each chain. Rules that keep the chain provable:
 *   - only a contiguous prefix is removed (everything before the first row that
 *     is still inside the retention window);
 *   - the newest row of a chain always stays, so new entries keep linking to it;
 *   - the hash of the last removed row is recorded in chain_prune_anchors, and
 *     verifyChain starts from it instead of from GENESIS;
 *   - the lock writers use is taken, so no entry is appended mid-prune.
 */
export const PRUNABLE_CHAINS = ["principal_audit_log", "firewall_decisions", "content_ingestion_log", "tool_call_audit"] as const;

export async function pruneAgentLogs(months = config.retentionAgentLogMonths): Promise<number> {
  if (config.deploymentMode === "self-hosted" || !(months > 0)) return 0;
  let removed = 0;
  for (const tenantId of await activeTenants()) {
    for (const table of PRUNABLE_CHAINS) {
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        await client.query("SELECT set_config('legion.audit_erasure', 'on', true)");
        await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [`${table}:${tenantId}`]);
        // First row still inside the window; if every row is old, keep the newest one.
        const boundary = (await client.query<{ seq: string }>(
          `SELECT coalesce(
              (SELECT min(seq) FROM ${table} WHERE chain_key = $1 AND occurred_at >= now() - make_interval(months => $2)),
              (SELECT max(seq) FROM ${table} WHERE chain_key = $1)) AS seq`,
          [tenantId, Math.floor(months)])).rows[0]?.seq;
        if (boundary) {
          const last = (await client.query<{ seq: string; hash: string }>(
            `SELECT seq, hash FROM ${table} WHERE chain_key = $1 AND seq < $2 ORDER BY seq DESC LIMIT 1`, [tenantId, boundary])).rows[0];
          if (last) {
            const r = await client.query(`DELETE FROM ${table} WHERE chain_key = $1 AND seq < $2`, [tenantId, boundary]);
            await client.query(
              `INSERT INTO chain_prune_anchors (table_name, tenant_id, anchor_hash, pruned_through_seq, pruned_rows)
               VALUES ($1, $2, $3, $4, $5)
               ON CONFLICT (table_name, tenant_id) DO UPDATE
                 SET anchor_hash = EXCLUDED.anchor_hash, pruned_through_seq = EXCLUDED.pruned_through_seq,
                     pruned_rows = chain_prune_anchors.pruned_rows + EXCLUDED.pruned_rows, pruned_at = now()`,
              [table, tenantId, last.hash, last.seq, r.rowCount ?? 0]);
            removed += r.rowCount ?? 0;
          }
        }
        await client.query("COMMIT");
      } catch (error) {
        await client.query("ROLLBACK").catch(() => {});
        throw error;
      } finally {
        client.release();
      }
    }
  }
  return removed;
}

export async function runRetention(): Promise<{ payments: number; audit: number; agentLogs: number }> {
  return { payments: await prunePaymentChecks(), audit: await pseudonymiseAudit(), agentLogs: await pruneAgentLogs() };
}
