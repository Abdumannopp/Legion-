/**
 * SOC core health for one workspace: what the engines decided and where work
 * is waiting. Counts only — no event text, no inputs.
 *
 * `shadow.divergent` is the number that matters before anyone considers
 * enforcement: how often existing code acted where the policy engine would
 * have asked a person, recorded only, or refused.
 */
import { queryOne } from "../db/pool.js";
import { runtimeStatus } from "../runtime/queue.js";

export async function socMetrics(tenantId: string) {
  const policy = await queryOne<{ total: number; allow: number; require_approval: number; record_only: number; deny: number; divergent: number; p95_latency_us: number | null }>(
    `SELECT count(*)::int AS total,
            count(*) FILTER (WHERE decision = 'ALLOW')::int AS allow,
            count(*) FILTER (WHERE decision = 'REQUIRE_APPROVAL')::int AS require_approval,
            count(*) FILTER (WHERE decision = 'RECORD_ONLY')::int AS record_only,
            count(*) FILTER (WHERE decision = 'DENY')::int AS deny,
            count(*) FILTER (WHERE enforcement = 'shadow' AND decision <> 'ALLOW' AND legacy_outcome IS NOT NULL AND legacy_outcome NOT LIKE 'skipped%')::int AS divergent,
            percentile_disc(0.95) WITHIN GROUP (ORDER BY latency_us) AS p95_latency_us
       FROM policy_decisions WHERE tenant_id = $1 AND created_at > now() - interval '24 hours'`,
    [tenantId],
  );
  const approvals = await queryOne<{ pending: number; oldest_pending_seconds: number | null; approved_24h: number; rejected_24h: number; expired_24h: number }>(
    `SELECT count(*) FILTER (WHERE status = 'pending' AND expires_at > now())::int AS pending,
            floor(extract(epoch FROM now() - min(created_at) FILTER (WHERE status = 'pending' AND expires_at > now())))::int AS oldest_pending_seconds,
            count(*) FILTER (WHERE status IN ('approved', 'consumed') AND decided_at > now() - interval '24 hours')::int AS approved_24h,
            count(*) FILTER (WHERE status = 'rejected' AND decided_at > now() - interval '24 hours')::int AS rejected_24h,
            count(*) FILTER (WHERE status = 'expired' AND decided_at > now() - interval '24 hours')::int AS expired_24h
       FROM approval_requests WHERE tenant_id = $1`,
    [tenantId],
  );
  const actions = await queryOne<Record<string, number>>(
    `SELECT count(*) FILTER (WHERE status = 'awaiting_approval')::int AS awaiting_approval,
            count(*) FILTER (WHERE status = 'queued')::int AS queued,
            count(*) FILTER (WHERE status = 'simulated' AND updated_at > now() - interval '24 hours')::int AS simulated_24h,
            count(*) FILTER (WHERE status = 'denied' AND created_at > now() - interval '24 hours')::int AS denied_24h,
            count(*) FILTER (WHERE status = 'failed')::int AS failed,
            count(*) FILTER (WHERE execution_mode NOT IN ('shadow', 'simulation'))::int AS live
       FROM action_requests WHERE tenant_id = $1`,
    [tenantId],
  );
  const workflows = await queryOne<{ runs_24h: number; failed_24h: number }>(
    `SELECT count(*)::int AS runs_24h, count(*) FILTER (WHERE status = 'failed')::int AS failed_24h
       FROM workflow_runs WHERE tenant_id = $1 AND created_at > now() - interval '24 hours'`,
    [tenantId],
  );
  const paused = (await queryOne<{ actions_paused: boolean }>("SELECT actions_paused FROM soc_controls WHERE tenant_id = $1", [tenantId]))?.actions_paused ?? false;
  return { window: "24h", paused, policy, shadow: { divergent: policy?.divergent ?? 0 }, approvals, actions, workflows, runtime: await runtimeStatus(tenantId) };
}
