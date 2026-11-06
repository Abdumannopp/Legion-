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
 * The audit log and the chained logs are append-only; these jobs are the deliberate,
 * documented erasure, done by bounded functions inside the database (migration
 * 0008_bounded_erasure.sql): never younger than 30 days, never a workspace on a legal hold.
 */
import { config } from "./config.js";
import { query } from "./db/pool.js";

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
  // F-02: the database does it (migration 0008), never touching entries younger than 30 days.
  for (const tenantId of await activeTenants()) {
    changed += (await query<{ n: number }>("SELECT legion_pseudonymise_audit($1, $2) AS n", [tenantId, Math.floor(months)])).rows[0]!.n;
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
  // F-02: legion_prune_chain (migration 0008) applies the rules above inside the database,
  // with a 30-day floor; the API's role cannot delete chain rows itself.
  for (const tenantId of await activeTenants()) {
    for (const table of PRUNABLE_CHAINS) {
      removed += (await query<{ n: number }>("SELECT legion_prune_chain($1, $2, $3) AS n", [table, tenantId, Math.floor(months)])).rows[0]!.n;
    }
  }
  return removed;
}

/**
 * SOC history (Task 10 core) grows with every alert: a policy decision per covered call, an action
 * request with its events, approvals, workflow runs, jobs and audit events — about 6.5 KB per action
 * (rate-limits-and-budgets.test.ts). Without a limit the database fills the disk and Legion stops.
 *
 * After SOC_RETENTION_DAYS this removes only what has FINISHED: pending approvals, queued or running
 * actions and jobs, and running workflows are never touched, whatever their age. The oldest SOC audit
 * events are removed like the agent logs: the hash of the last removed event is kept in
 * chain_prune_anchors, so verifyAuditChain() still proves the remaining chain (and still fails if a
 * surviving event was changed). The newest audit event is always kept. Legal holds are skipped.
 */
export const SOC_TERMINAL_ACTIONS = ["denied", "recorded", "rejected", "expired", "cancelled", "simulated", "failed"] as const;

export async function pruneSocHistory(days = config.retentionSocDays): Promise<Record<string, number>> {
  const counts: Record<string, number> = { soc_jobs: 0, action_requests: 0, approval_requests: 0, policy_decisions: 0, workflow_runs: 0, soc_audit_events: 0 };
  if (!(days > 0)) return counts;
  // F-02: legion_prune_soc (migration 0008) does the whole pass in one transaction, with the
  // finished states fixed in SQL and a 30-day floor.
  for (const tenantId of await activeTenants()) {
    const r = (await query<{ c: Record<string, number> }>("SELECT legion_prune_soc($1, $2) AS c", [tenantId, Math.floor(days)])).rows[0]!.c;
    for (const [k, n] of Object.entries(r)) counts[k] = (counts[k] ?? 0) + n;
  }
  return counts;
}

export async function runRetention(): Promise<{ payments: number; audit: number; agentLogs: number; soc: Record<string, number> }> {
  return { payments: await prunePaymentChecks(), audit: await pseudonymiseAudit(), agentLogs: await pruneAgentLogs(), soc: await pruneSocHistory() };
}
