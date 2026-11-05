/**
 * Prometheus metrics (text exposition format 0.0.4) for operators.
 *
 * Platform-wide counts only: no tenant ids, no recipients, no alert or action
 * text, no payloads. The endpoint is not public — it exists only when
 * HEALTH_METRICS_TOKEN is set and requires it (see index.ts).
 *
 * What a pilot needs to see: is the runtime worker alive, is work piling up,
 * is anything dead or stuck, are approvals waiting, is any workspace paused,
 * how often do shadow decisions diverge, and — above all — is any action
 * running outside shadow/simulation (that number must be 0).
 */
import { pool, query } from "./db/pool.js";
import { aiCircuit } from "./ai.js";
import { queueMetrics, workerStatus } from "./outbox.js";
import { RUNNING_STALE_SECONDS } from "./actions/engine.js";
import { runtimeHealth } from "./runtime/worker.js";
import { currentAuditKeyId } from "./audit/events.js";
import { renderHttpStats } from "./http-stats.js";
import { config } from "./config.js";

type Sample = { name: string; help: string; type: "gauge" | "counter"; values: Array<{ labels?: Record<string, string>; value: number }> };

const esc = (v: string) => v.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n");
export function render(samples: Sample[]): string {
  const out: string[] = [];
  for (const s of samples) {
    out.push(`# HELP ${s.name} ${s.help}`, `# TYPE ${s.name} ${s.type}`);
    for (const v of s.values) {
      const l = v.labels ? `{${Object.entries(v.labels).map(([k, x]) => `${k}="${esc(x)}"`).join(",")}}` : "";
      out.push(`${s.name}${l} ${Number.isFinite(v.value) ? v.value : 0}`);
    }
  }
  return out.join("\n") + "\n";
}

const g = (name: string, help: string, value: number, labels?: Record<string, string>): Sample => ({ name, help, type: "gauge", values: [{ labels, value }] });
const byLabel = (name: string, help: string, label: string, keys: readonly string[], rows: Array<Record<string, unknown>>, key: string): Sample => ({
  name, help, type: "gauge",
  values: keys.map((k) => ({ labels: { [label]: k }, value: Number(rows.find((r) => r[key] === k)?.n ?? 0) })),
});

/**
 * Every statement below is partitioned BY TENANT (GROUP BY tenant_id) and the
 * totals are summed here, so no query reads across workspaces unscoped (the
 * tenant-query guard test holds these tables to that rule) and no tenant id
 * leaves this file.
 */
const sum = (rows: Array<Record<string, unknown>>, key: string) => rows.reduce((a, r) => a + Number(r[key] ?? 0), 0);
const sumBy = (rows: Array<Record<string, unknown>>, keyCol: string) => {
  const m = new Map<string, number>();
  for (const r of rows) m.set(String(r[keyCol]), (m.get(String(r[keyCol])) ?? 0) + Number(r.n ?? 0));
  return [...m].map(([k, n]) => ({ k, n }));
};
const maxOf = (rows: Array<Record<string, unknown>>, key: string) => rows.reduce((a, r) => Math.max(a, Number(r[key] ?? 0)), 0);

export async function collectMetrics(): Promise<string> {
  const many = async (sql: string) => (await query(sql)).rows as Array<Record<string, unknown>>;

  const jobs = sumBy(await many("SELECT tenant_id, status AS k, count(*)::int AS n FROM soc_jobs GROUP BY tenant_id, status"), "k");
  const jobAges = await many(`SELECT tenant_id,
      coalesce(floor(extract(epoch FROM now() - min(run_after) FILTER (WHERE status = 'queued' AND run_after <= now()))), 0)::int AS oldest_due,
      count(*) FILTER (WHERE status = 'running' AND lease_until < now())::int AS expired_leases
    FROM soc_jobs GROUP BY tenant_id`);
  const actions = sumBy(await many("SELECT tenant_id, status AS k, count(*)::int AS n FROM action_requests GROUP BY tenant_id, status"), "k");
  const act = await many(`SELECT tenant_id,
      count(*) FILTER (WHERE execution_mode NOT IN ('shadow', 'simulation'))::int AS live,
      count(*) FILTER (WHERE status = 'running' AND updated_at < now() - make_interval(secs => ${Number(RUNNING_STALE_SECONDS)}))::int AS stuck
    FROM action_requests GROUP BY tenant_id`);
  const appr = await many(`SELECT tenant_id,
      count(*) FILTER (WHERE status = 'pending' AND expires_at > now())::int AS pending,
      coalesce(floor(extract(epoch FROM now() - min(created_at) FILTER (WHERE status = 'pending' AND expires_at > now()))), 0)::int AS oldest,
      count(*) FILTER (WHERE status = 'approved')::int AS approved_unused
    FROM approval_requests GROUP BY tenant_id`);
  const paused = await many("SELECT tenant_id, count(*)::int AS n FROM soc_controls WHERE actions_paused GROUP BY tenant_id");
  const pol = sumBy(await many("SELECT tenant_id, decision AS k, count(*)::int AS n FROM policy_decisions WHERE created_at > now() - interval '5 minutes' GROUP BY tenant_id, decision"), "k");
  const div = await many(`SELECT tenant_id, count(*)::int AS n FROM policy_decisions
    WHERE created_at > now() - interval '24 hours' AND enforcement = 'shadow' AND decision <> 'ALLOW' AND legacy_outcome IS NOT NULL AND legacy_outcome NOT LIKE 'skipped%'
    GROUP BY tenant_id`);
  const audit = await many("SELECT tenant_id, count(*)::int AS n FROM soc_audit_events GROUP BY tenant_id");
  // Workspaces whose newest audit event was signed with a different key than this process holds.
  const heads = await many("SELECT DISTINCT ON (tenant_id) tenant_id, key_id FROM soc_audit_events ORDER BY tenant_id, seq DESC");
  const keyMismatch = heads.filter((h) => h.key_id !== currentAuditKeyId()).length;
  const wf = await many("SELECT tenant_id, count(*) FILTER (WHERE status = 'failed')::int AS failed, count(*)::int AS total FROM workflow_runs WHERE created_at > now() - interval '1 hour' GROUP BY tenant_id");
  const outbox = await queueMetrics();
  const rt = runtimeHealth();
  const ob = workerStatus();

  const samples: Sample[] = [
    g("legion_up", "The API answered.", 1),
    g("legion_process_uptime_seconds", "Seconds since this process started.", Math.round(process.uptime())),
    g("legion_build_info", "Version of this instance.", 1, { version: config.version, mode: config.deploymentMode }),
    // --- SOC runtime
    g("legion_soc_runtime_worker_running", "1 when this instance runs the SOC job worker.", rt.running ? 1 : 0),
    g("legion_soc_runtime_last_tick_age_seconds", "Seconds since this instance's SOC worker finished a pass (-1: never).", rt.last_tick_seconds_ago ?? -1),
    { name: "legion_soc_runtime_ticks_total", help: "SOC worker passes since start.", type: "counter", values: [{ value: rt.ticks }] },
    { name: "legion_soc_runtime_tick_errors_total", help: "SOC worker passes that threw.", type: "counter", values: [{ value: rt.errors }] },
    byLabel("legion_soc_jobs", "SOC jobs by status.", "status", ["queued", "running", "done", "dead"], jobs, "k"),
    g("legion_soc_jobs_oldest_due_age_seconds", "Age of the longest-waiting job that is due now.", maxOf(jobAges, "oldest_due")),
    g("legion_soc_jobs_expired_leases", "Running jobs whose worker lease ran out (a worker died).", sum(jobAges, "expired_leases")),
    // --- actions / approvals
    byLabel("legion_soc_actions", "Action requests by status.", "status", ["denied", "recorded", "awaiting_approval", "rejected", "expired", "cancelled", "queued", "running", "simulated", "failed"], actions, "k"),
    g("legion_soc_actions_live", "Actions in any mode other than shadow/simulation. Must be 0 during the pilot.", sum(act, "live")),
    g("legion_soc_actions_stuck_running", "Actions stuck in running past the recovery window.", sum(act, "stuck")),
    g("legion_soc_approvals_pending", "Approval requests waiting for a person.", sum(appr, "pending")),
    g("legion_soc_approvals_oldest_pending_age_seconds", "Age of the longest-waiting approval request.", maxOf(appr, "oldest")),
    g("legion_soc_approvals_approved_unused", "Approved requests not yet used (held by a pause, or waiting for the next sync).", sum(appr, "approved_unused")),
    g("legion_soc_workspaces_paused", "Workspaces whose emergency stop is on.", sum(paused, "n")),
    // --- policy / audit / workflows
    byLabel("legion_soc_policy_decisions_5m", "Policy decisions in the last 5 minutes.", "decision", ["ALLOW", "REQUIRE_APPROVAL", "RECORD_ONLY", "DENY"], pol, "k"),
    g("legion_soc_shadow_divergent_24h", "Shadow decisions in 24h where existing code acted but the policy would not have allowed it.", sum(div, "n")),
    g("legion_soc_audit_events", "Events in the SOC audit chains.", sum(audit, "n")),
    g("legion_soc_audit_key_mismatch_workspaces", "Workspaces whose audit chain was signed with a different key than this process has (SOC_AUDIT_KEY wrong or changed). Appending is refused for them.", keyMismatch),
    g("legion_soc_workflow_runs_1h", "Workflow runs in the last hour.", sum(wf, "total")),
    g("legion_soc_workflow_runs_failed_1h", "Failed workflow runs in the last hour.", sum(wf, "failed")),
    // --- notifications
    g("legion_outbox_pending", "Notifications waiting.", outbox.pending),
    g("legion_outbox_dead", "Notifications that failed permanently.", outbox.dead),
    g("legion_outbox_oldest_pending_age_seconds", "Age of the oldest undelivered notification.", outbox.oldest_pending_age_seconds ?? 0),
    g("legion_outbox_worker_running", "1 when this instance runs the notification worker.", ob.running ? 1 : 0),
    // --- dependencies
    g("legion_ai_circuit_open", "1 while the AI provider circuit breaker is open.", aiCircuit().state === "open" ? 1 : 0),
    g("legion_db_pool_total", "Database connections open.", pool.totalCount),
    g("legion_db_pool_waiting", "Requests waiting for a database connection.", pool.waitingCount),
  ];
  return render(samples) + renderHttpStats();
}
