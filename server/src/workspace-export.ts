/**
 * Workspace export: everything a customer's workspace holds, as one JSON file,
 * for the customer's own records, to move elsewhere, or before leaving.
 *
 * - Streamed in batches (a busy workspace has hundreds of thousands of alerts).
 * - Only this workspace's rows: every query is scoped by tenant_id.
 * - No secrets: no password hashes, tokens, MFA seeds or sensor credentials, and
 *   no payment account hashes. People appear by email, role and status.
 */
import type { Response } from "express";
import { query } from "./db/pool.js";

const BATCH = 1000;
const TABLES: Array<{ name: string; table: string; key: string; strip?: string[] }> = [
  { name: "alerts", table: "alerts", key: "id" },
  { name: "assets", table: "assets", key: "id" },
  { name: "audit_log", table: "audit_log", key: "id" },
  { name: "payment_checks", table: "payment_checks", key: "id", strip: ["beneficiary_hash"] },
  { name: "ip_blocks", table: "ip_blocks", key: "id" },
  { name: "attack_campaigns", table: "attack_campaigns", key: "id" },
];

export const EXPORT_FORMAT = "legion-workspace-export/1";

export async function streamWorkspaceExport(tenantId: string, res: Response): Promise<Record<string, number>> {
  const counts: Record<string, number> = {};
  const write = (text: string) => new Promise<void>((ok) => { res.write(text) ? ok() : res.once("drain", ok); });

  const tenant = (await query(
    `SELECT id, name, created_at, trial_ends_at, notification_email, timezone, locale, currency, region, plan_override
       FROM tenants WHERE id = $1`, [tenantId])).rows[0];
  const members = (await query(
    `SELECT u.email, m.role, m.status, m.created_at
       FROM workspace_memberships m JOIN users u ON u.id = m.user_id
      WHERE m.tenant_id = $1 ORDER BY u.email`, [tenantId])).rows;

  await write(`{"format":${JSON.stringify(EXPORT_FORMAT)},"exported_at":${JSON.stringify(new Date().toISOString())},` +
    `"workspace":${JSON.stringify(tenant ?? null)},"members":${JSON.stringify(members)}`);
  counts.members = members.length;

  for (const t of TABLES) {
    await write(`,${JSON.stringify(t.name)}:[`);
    let last = "";
    let n = 0;
    for (;;) {
      const rows = (await query<{ k: string; j: Record<string, unknown> }>(
        `SELECT ${t.key}::text AS k, to_jsonb(x) AS j FROM ${t.table} x
          WHERE tenant_id = $1 AND ${t.key}::text > $2 ORDER BY ${t.key}::text LIMIT ${BATCH}`,
        [tenantId, last])).rows;
      if (!rows.length) break;
      const chunk = rows.map((r) => { for (const s of t.strip ?? []) delete r.j[s]; return JSON.stringify(r.j); }).join(",");
      await write((n ? "," : "") + chunk);
      n += rows.length;
      last = rows[rows.length - 1]!.k;
      if (rows.length < BATCH) break;
    }
    await write("]");
    counts[t.name] = n;
  }
  await write(`,"counts":${JSON.stringify(counts)}}`);
  res.end();
  return counts;
}
